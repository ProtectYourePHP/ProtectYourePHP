--TEST--
pyp: extension is loaded and reports its version
--SKIPIF--
<?php if (!extension_loaded('pyp')) die('skip pyp extension not loaded'); ?>
--FILE--
<?php
var_dump(extension_loaded('pyp'));
$info = pyp_ext_info();
var_dump($info['version'] === PYP_EXT_VERSION);
var_dump($info['loader_api'] === PYP_LOADER_API);
var_dump($info['features']['macs']);
var_dump($info['features']['compile_hook']);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
