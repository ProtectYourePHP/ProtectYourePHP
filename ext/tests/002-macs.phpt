--TEST--
pyp: pyp_macs() returns normalised, unique MAC addresses
--SKIPIF--
<?php if (!extension_loaded('pyp')) die('skip pyp extension not loaded'); ?>
--FILE--
<?php
$macs = pyp_macs();
var_dump(is_array($macs));
var_dump(array_is_list($macs));
var_dump(count($macs) === count(array_unique($macs)));
foreach ($macs as $mac) {
    if (!preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', $mac) || $mac === '00:00:00:00:00:00') {
        echo "bad: $mac\n";
    }
}
try {
    pyp_macs(1);
} catch (ArgumentCountError $e) {
    echo "ArgumentCountError\n";
}
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
ArgumentCountError
