/*
 * ProtectYourePHP native extension ("pyp")
 *
 * Optional companion to loader/pyp-loader.php. The PHP loader detects the
 * extension (extension_loaded('pyp')) and uses its native helpers.
 */
#ifndef PHP_PYP_H
#define PHP_PYP_H

extern zend_module_entry pyp_module_entry;
#define phpext_pyp_ptr &pyp_module_entry

#define PHP_PYP_VERSION "0.3.0"

/* Version of the contract between this extension and pyp-loader.php.
 * Bump when functions are added/changed so the loader can feature-detect. */
#define PHP_PYP_LOADER_API 2

#if defined(ZTS) && defined(COMPILE_DL_PYP)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif /* PHP_PYP_H */
