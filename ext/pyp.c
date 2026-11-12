/*
 * ProtectYourePHP native extension ("pyp") - version 0.1.0
 *
 * Today this extension provides native helpers for pyp-loader.php:
 *   - pyp_macs()      reliable MAC address detection without exec()
 *   - pyp_ext_info()  feature detection for the loader
 *
 * It is the place where the native loader will grow (see docs/native-extension.md):
 * a zend_compile_file hook that decrypts PYP containers in C, so decrypted
 * source never reaches userland and OPcache can cache the result.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
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
	add_assoc_bool(&features, "compile_hook", 0);
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
	php_info_print_table_row(2, "Native compile hook", "not yet available");
	php_info_print_table_end();
}
/* }}} */

zend_module_entry pyp_module_entry = {
	STANDARD_MODULE_HEADER,
	"pyp",
	ext_functions,
	PHP_MINIT(pyp),
	NULL,                /* MSHUTDOWN */
	NULL,                /* RINIT */
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
