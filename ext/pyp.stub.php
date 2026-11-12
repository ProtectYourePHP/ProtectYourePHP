<?php

/**
 * Function signatures of the pyp extension.
 * pyp_arginfo.h can be regenerated with php-src's build/gen_stub.php:
 *   php /path/to/php-src/build/gen_stub.php ext/pyp.stub.php
 * (constants are registered by hand in PHP_MINIT, see pyp.c)
 */

/** @var string */
const PYP_EXT_VERSION = UNKNOWN;

/** @var int */
const PYP_LOADER_API = UNKNOWN;

/**
 * MAC addresses of all non-loopback network interfaces,
 * lower case, colon separated ("aa:bb:cc:dd:ee:ff"), without duplicates.
 *
 * @return array<int, string>
 */
function pyp_macs(): array {}

/**
 * Build information: version, loader_api and the list of native features.
 *
 * @return array<string, mixed>
 */
function pyp_ext_info(): array {}
