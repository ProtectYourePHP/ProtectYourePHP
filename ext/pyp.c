/*
 * ProtectYourePHP native extension ("pyp") - version 0.2.0
 *
 *   - compile hook    runs files built with "pyp encode --require-ext": the decrypted source
 *                     goes straight to the compiler and never reaches PHP code
 *   - pyp_macs()      reliable MAC address detection without exec()
 *   - pyp_ext_info()  feature detection for the loader
 *
 * Next steps (see docs/native-extension.md): license check, key handling and decryption
 * entirely in C, and OPcache support for protected files.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/json/php_json.h"
#include "zend_exceptions.h"
#include "zend_stream.h"
#include "zend_virtual_cwd.h"
#include "main/php_streams.h"
#include "php_pyp.h"
#include "pyp_arginfo.h"

#include <string.h>

#ifdef PHP_WIN32
# include <winsock2.h>
# include <ws2ipdef.h>
# include <iphlpapi.h>
#else
# ifdef HAVE_IFADDRS_H
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <ifaddrs.h>
#  ifdef HAVE_NETPACKET_PACKET_H
#   include <netpacket/packet.h>
#  endif
#  ifdef HAVE_NET_IF_DL_H
#   include <net/if_dl.h>
#  endif
# endif
#endif

/* Append "aa:bb:cc:dd:ee:ff" to arr unless it is all zero or already present. */
static void pyp_add_mac(zval *arr, const unsigned char *addr, size_t len)
{
	char buf[18];
	size_t i;
	int nonzero = 0;
	zval *entry;

	if (addr == NULL || len != 6) {
		return;
	}
	for (i = 0; i < len; i++) {
		if (addr[i] != 0) {
			nonzero = 1;
			break;
		}
	}
	if (!nonzero) {
		return;
	}
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(arr), entry) {
		if (Z_TYPE_P(entry) == IS_STRING && strcmp(Z_STRVAL_P(entry), buf) == 0) {
			return;
		}
	} ZEND_HASH_FOREACH_END();

	add_next_index_string(arr, buf);
}

/* {{{ pyp_macs(): array */
ZEND_FUNCTION(pyp_macs)
{
	ZEND_PARSE_PARAMETERS_NONE();

	array_init(return_value);

#ifdef PHP_WIN32
	{
		ULONG size = 16 * 1024;
		ULONG ret;
		int attempt;
		IP_ADAPTER_ADDRESSES *addrs = NULL, *p;
		const ULONG flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST
			| GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

		for (attempt = 0; attempt < 3; attempt++) {
			addrs = (IP_ADAPTER_ADDRESSES *) emalloc(size);
			ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addrs, &size);
			if (ret != ERROR_BUFFER_OVERFLOW) {
				break;
			}
			efree(addrs);
			addrs = NULL;
		}
		if (addrs != NULL) {
			if (ret == NO_ERROR) {
				for (p = addrs; p != NULL; p = p->Next) {
					if (p->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
						pyp_add_mac(return_value, p->PhysicalAddress, p->PhysicalAddressLength);
					}
				}
			}
			efree(addrs);
		}
	}
#elif defined(HAVE_IFADDRS_H)
	{
		struct ifaddrs *ifa = NULL, *p;

		if (getifaddrs(&ifa) == 0) {
			for (p = ifa; p != NULL; p = p->ifa_next) {
				if (p->ifa_addr == NULL) {
					continue;
				}
# ifdef HAVE_NETPACKET_PACKET_H
				if (p->ifa_addr->sa_family == AF_PACKET) {
					const struct sockaddr_ll *sll = (const struct sockaddr_ll *) p->ifa_addr;
					pyp_add_mac(return_value, sll->sll_addr, sll->sll_halen);
				}
# elif defined(HAVE_NET_IF_DL_H) && defined(AF_LINK)
				if (p->ifa_addr->sa_family == AF_LINK) {
					const struct sockaddr_dl *sdl = (const struct sockaddr_dl *) p->ifa_addr;
					pyp_add_mac(return_value, (const unsigned char *) LLADDR(sdl), sdl->sdl_alen);
				}
# endif
			}
			freeifaddrs(ifa);
		}
	}
#endif
}
/* }}} */

/* ------------------------------------------------------------------------------------------
 * Compile hook (files built with "pyp encode --require-ext")
 *
 * The hook recognises a PYP container, asks pyp-loader.php for the file key (licensing stays
 * in the PHP loader for now, loader API 2), decrypts and hands the source straight to the
 * compiler under the file's real path. The decrypted source never becomes a PHP value.
 *
 * It is installed on the first request, so it sits in front of OPcache: protected files are
 * compiled by the engine's own compiler and are not stored in the OPcache (yet), which keeps
 * the license check on every request.
 * ------------------------------------------------------------------------------------------ */

#define PYP_MAX_HEADER 65536
#define PYP_MAX_CONTAINER (64 * 1024 * 1024)

static zend_op_array *(*pyp_base_compile_file)(zend_file_handle *file_handle, int type) = NULL;
static zend_op_array *(*pyp_prev_compile_file)(zend_file_handle *file_handle, int type) = NULL;
static int pyp_hooked = 0;
#ifdef ZTS
static MUTEX_T pyp_hook_mutex = NULL;
#endif

typedef struct _pyp_source {
	zend_string *src;
	size_t pos;
} pyp_source;

static ssize_t pyp_source_read(void *handle, char *buf, size_t len)
{
	pyp_source *s = (pyp_source *) handle;
	size_t left = ZSTR_LEN(s->src) - s->pos;

	if (len > left) {
		len = left;
	}
	if (len > 0) {
		memcpy(buf, ZSTR_VAL(s->src) + s->pos, len);
		s->pos += len;
	}
	return (ssize_t) len;
}

static size_t pyp_source_size(void *handle)
{
	return ZSTR_LEN(((pyp_source *) handle)->src);
}

static void pyp_source_close(void *handle)
{
	pyp_source *s = (pyp_source *) handle;

	if (!ZSTR_IS_INTERNED(s->src) && GC_REFCOUNT(s->src) == 1) {
		ZEND_SECURE_ZERO(ZSTR_VAL(s->src), ZSTR_LEN(s->src));
	}
	zend_string_release(s->src);
	efree(s);
}

/* Compile src (ownership is taken) as the content of the file "path". */
static zend_op_array *pyp_compile_source(zend_string *path, zend_string *src, zend_file_handle *orig, int type)
{
	zend_file_handle mem;
	zend_op_array *op_array;
	pyp_source *s = (pyp_source *) emalloc(sizeof(pyp_source));

	s->src = src;
	s->pos = 0;

	zend_stream_init_filename_ex(&mem, path);
	mem.type = ZEND_HANDLE_STREAM;
	mem.handle.stream.handle = s;
	mem.handle.stream.isatty = 0;
	mem.handle.stream.reader = pyp_source_read;
	mem.handle.stream.fsizer = pyp_source_size;
	mem.handle.stream.closer = pyp_source_close;
	mem.primary_script = orig->primary_script;

	op_array = pyp_base_compile_file(&mem, type);
	zend_destroy_file_handle(&mem);

	if (op_array) {
		zend_hash_add_empty_element(&EG(included_files), path);
	}
	return op_array;
}

static uint32_t pyp_be32(const unsigned char *p)
{
	return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

/* Read exactly len bytes (PHP streams: no platform specific file API, honours open_basedir). */
static int pyp_read_full(php_stream *stream, char *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t n = php_stream_read(stream, buf + done, len - done);

		if (n <= 0) {
			return 0;
		}
		done += (size_t) n;
	}
	return 1;
}

/* MAGIC | u32 headerLen | header(JSON) | ciphertext | u32 lengthOfEverythingBefore   (at the end of the file) */
static int pyp_read_container(const char *path, zend_string **header, zend_string **cipher)
{
	php_stream *stream = php_stream_open_wrapper((char *) path, "rb", IGNORE_URL, NULL);
	unsigned char b[8];
	zend_off_t size;
	uint32_t len, hl;
	int ok = 0;

	*header = NULL;
	*cipher = NULL;
	if (!stream) {
		return 0;
	}
	if (php_stream_seek(stream, -4, SEEK_END) != 0 || (size = php_stream_tell(stream)) < 8
		|| !pyp_read_full(stream, (char *) b, 4)) {
		goto done;
	}
	len = pyp_be32(b);
	if (len < 10 || len > PYP_MAX_CONTAINER || (zend_off_t) len > size) {
		goto done;
	}
	if (php_stream_seek(stream, size - (zend_off_t) len, SEEK_SET) != 0 || !pyp_read_full(stream, (char *) b, 8)
		|| memcmp(b, "PYP1", 4) != 0) {
		goto done;
	}
	hl = pyp_be32(b + 4);
	if (hl < 2 || hl > PYP_MAX_HEADER || hl + 8 > len) {
		goto done;
	}
	*header = zend_string_alloc(hl, 0);
	*cipher = zend_string_alloc(len - 8 - hl, 0);
	if (!pyp_read_full(stream, ZSTR_VAL(*header), hl)
		|| !pyp_read_full(stream, ZSTR_VAL(*cipher), ZSTR_LEN(*cipher))) {
		zend_string_release(*header);
		zend_string_release(*cipher);
		*header = NULL;
		*cipher = NULL;
		goto done;
	}
	ZSTR_VAL(*header)[hl] = 0;
	ZSTR_VAL(*cipher)[ZSTR_LEN(*cipher)] = 0;
	ok = 1;
done:
	php_stream_close(stream);
	return ok;
}

static int pyp_loader_available(void)
{
	zend_string *name = zend_string_init(ZEND_STRL("Pyp\\Loader"), 0);
	zend_class_entry *ce = zend_lookup_class_ex(name, NULL, ZEND_FETCH_CLASS_NO_AUTOLOAD);

	zend_string_release(name);
	return ce != NULL;
}

/* Make sure \Pyp\Loader is defined: require "<dir of the file>/<header.loader>". */
static int pyp_ensure_loader(zend_string *path, zval *rel)
{
	char *dir;
	size_t dir_len;
	zend_string *full;
	zend_file_handle fh;

	if (pyp_loader_available()) {
		return 1;
	}
	if (!rel || Z_TYPE_P(rel) != IS_STRING || Z_STRLEN_P(rel) == 0 || Z_STRLEN_P(rel) > 1024
		|| strlen(Z_STRVAL_P(rel)) != Z_STRLEN_P(rel) || strstr(Z_STRVAL_P(rel), "://") != NULL) {
		return 0;
	}
	dir = estrndup(ZSTR_VAL(path), ZSTR_LEN(path));
	dir_len = zend_dirname(dir, ZSTR_LEN(path));
	full = strpprintf(0, "%.*s%c%s", (int) dir_len, dir, DEFAULT_SLASH, Z_STRVAL_P(rel));
	efree(dir);

	zend_stream_init_filename_ex(&fh, full);
	zend_execute_scripts(ZEND_REQUIRE, NULL, 1, &fh);
	zend_destroy_file_handle(&fh);
	zend_string_release(full);

	return !EG(exception) && pyp_loader_available();
}

/* Call a PHP function/static method by name. Returns 1 when it returned without an exception. */
static int pyp_call(const char *name, zval *retval, uint32_t argc, zval *argv)
{
	zval fn;
	int ok;

	ZVAL_STRING(&fn, name);
	ZVAL_UNDEF(retval);
	ok = call_user_function(NULL, NULL, &fn, retval, argc, argv) == SUCCESS && !EG(exception);
	zval_ptr_dtor(&fn);
	return ok;
}

/* The decrypted source of a --require-ext file, or NULL (then the loader knows the reason). */
static zend_string *pyp_decrypt(zend_string *path, zend_string *header, zend_string *cipher)
{
	zval key, arg, args[4], plain;
	zend_string *src = NULL;

	ZVAL_STR_COPY(&arg, path);
	if (!pyp_call("Pyp\\Loader::extKey", &key, 1, &arg)) {
		zval_ptr_dtor(&arg);
		zval_ptr_dtor(&key);
		return NULL;
	}
	zval_ptr_dtor(&arg);

	if (Z_TYPE(key) == IS_STRING && Z_STRLEN(key) == 32 + 24) {
		ZVAL_STR_COPY(&args[0], cipher);
		ZVAL_STR_COPY(&args[1], header);                         /* authenticated, not encrypted */
		ZVAL_STRINGL(&args[2], Z_STRVAL(key) + 32, 24);          /* nonce */
		ZVAL_STRINGL(&args[3], Z_STRVAL(key), 32);               /* file key */

		if (pyp_call("sodium_crypto_aead_xchacha20poly1305_ietf_decrypt", &plain, 4, args) && Z_TYPE(plain) == IS_STRING) {
			src = zend_string_copy(Z_STR(plain));
		} else if (EG(exception)) {
			zend_clear_exception();
		}
		zval_ptr_dtor(&plain);
		ZEND_SECURE_ZERO(Z_STRVAL(args[3]), Z_STRLEN(args[3]));
		zval_ptr_dtor(&args[0]);
		zval_ptr_dtor(&args[1]);
		zval_ptr_dtor(&args[2]);
		zval_ptr_dtor(&args[3]);

		if (!src) {
			zval type, ignored;

			ZVAL_STRING(&type, "corrupt");
			pyp_call("Pyp\\Loader::extReject", &ignored, 1, &type);
			zval_ptr_dtor(&type);
			zval_ptr_dtor(&ignored);
		}
	}
	if (Z_TYPE(key) == IS_STRING && !ZSTR_IS_INTERNED(Z_STR(key))) {
		ZEND_SECURE_ZERO(Z_STRVAL(key), Z_STRLEN(key));
	}
	zval_ptr_dtor(&key);
	return src;
}

static zend_op_array *pyp_compile_file(zend_file_handle *file_handle, int type)
{
	zend_string *path, *header = NULL, *cipher = NULL, *src;
	zval h, *ext, *kind;
	zend_op_array *op_array;

	path = file_handle->opened_path ? file_handle->opened_path : file_handle->filename;
	if (!path || ZSTR_LEN(path) == 0 || strstr(ZSTR_VAL(path), "://") != NULL
		|| !pyp_read_container(ZSTR_VAL(path), &header, &cipher)) {
		return pyp_prev_compile_file(file_handle, type);
	}

	ZVAL_UNDEF(&h);
	if (php_json_decode_ex(&h, ZSTR_VAL(header), ZSTR_LEN(header), PHP_JSON_OBJECT_AS_ARRAY, 16) != SUCCESS
		|| Z_TYPE(h) != IS_ARRAY
		|| (ext = zend_hash_str_find(Z_ARRVAL(h), ZEND_STRL("ext"))) == NULL || !zend_is_true(ext)
		|| (kind = zend_hash_str_find(Z_ARRVAL(h), ZEND_STRL("kind"))) == NULL
		|| Z_TYPE_P(kind) != IS_STRING || !zend_string_equals_literal(Z_STR_P(kind), "php")) {
		/* not built for the extension: the file's PHP stub and pyp-loader.php handle it */
		zval_ptr_dtor(&h);
		zend_string_release(header);
		zend_string_release(cipher);
		if (EG(exception)) {
			zend_clear_exception();
		}
		return pyp_prev_compile_file(file_handle, type);
	}

	path = zend_string_copy(path);
	src = NULL;
	if (pyp_ensure_loader(path, zend_hash_str_find(Z_ARRVAL(h), ZEND_STRL("loader")))) {
		src = pyp_decrypt(path, header, cipher);
	}
	zval_ptr_dtor(&h);
	zend_string_release(header);
	zend_string_release(cipher);

	if (EG(exception)) {
		if (src) {
			zend_string_release(src);
		}
		zend_string_release(path);
		return NULL;
	}
	if (!src) {
		if (!pyp_loader_available()) {
			zend_string_release(path);
			zend_error_noreturn(E_COMPILE_ERROR, "ProtectYourePHP: pyp-loader.php was not found for this protected file");
		}
		/* refused (license, key, corrupt file): the loader reports it when this runs */
		src = zend_string_init(ZEND_STRL("<?php \\Pyp\\Loader::extFail();"), 0);
	}
	op_array = pyp_compile_source(path, src, file_handle, type);
	zend_string_release(path);
	return op_array;
}

static void pyp_install_hook(void)
{
	if (pyp_hooked) {
		return;
	}
#ifdef ZTS
	tsrm_mutex_lock(pyp_hook_mutex);
#endif
	if (!pyp_hooked) {
		pyp_prev_compile_file = zend_compile_file;
		zend_compile_file = pyp_compile_file;
		pyp_hooked = 1;
	}
#ifdef ZTS
	tsrm_mutex_unlock(pyp_hook_mutex);
#endif
}

/* {{{ pyp_ext_info(): array */
ZEND_FUNCTION(pyp_ext_info)
{
	zval features;

	ZEND_PARSE_PARAMETERS_NONE();

	array_init(return_value);
	add_assoc_string(return_value, "version", PHP_PYP_VERSION);
	add_assoc_long(return_value, "loader_api", PHP_PYP_LOADER_API);

	array_init(&features);
	add_assoc_bool(&features, "macs", 1);
	add_assoc_bool(&features, "compile_hook", 1);
	add_assoc_zval(return_value, "features", &features);
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(pyp)
{
#if defined(ZTS) && defined(COMPILE_DL_PYP)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	REGISTER_STRING_CONSTANT("PYP_EXT_VERSION", PHP_PYP_VERSION, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PYP_LOADER_API", PHP_PYP_LOADER_API, CONST_PERSISTENT);
	pyp_base_compile_file = zend_compile_file;   /* the compiler without OPcache in front of it */
#ifdef ZTS
	pyp_hook_mutex = tsrm_mutex_alloc();
#endif
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION */
PHP_MSHUTDOWN_FUNCTION(pyp)
{
	if (pyp_hooked && zend_compile_file == pyp_compile_file) {
		zend_compile_file = pyp_prev_compile_file;
	}
	pyp_hooked = 0;
#ifdef ZTS
	if (pyp_hook_mutex) {
		tsrm_mutex_free(pyp_hook_mutex);
		pyp_hook_mutex = NULL;
	}
#endif
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION */
PHP_RINIT_FUNCTION(pyp)
{
#if defined(ZTS) && defined(COMPILE_DL_PYP)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	pyp_install_hook();   /* on the first request: after OPcache has installed its own hook */
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION */
PHP_MINFO_FUNCTION(pyp)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "PYP (ProtectYourePHP) support", "enabled");
	php_info_print_table_row(2, "Version", PHP_PYP_VERSION);
	php_info_print_table_row(2, "Loader API", ZEND_TOSTR(PHP_PYP_LOADER_API));
	php_info_print_table_row(2, "Native compile hook", "enabled (files built with --require-ext)");
	php_info_print_table_end();
}
/* }}} */

zend_module_entry pyp_module_entry = {
	STANDARD_MODULE_HEADER,
	"pyp",
	ext_functions,
	PHP_MINIT(pyp),
	PHP_MSHUTDOWN(pyp),
	PHP_RINIT(pyp),
	NULL,                /* RSHUTDOWN */
	PHP_MINFO(pyp),
	PHP_PYP_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PYP
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(pyp)
#endif
