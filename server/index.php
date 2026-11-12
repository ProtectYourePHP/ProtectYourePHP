<?php
// Reference license endpoint.  Run:  php bin/pyp serve   (or point any web server's document root here)
// Keep the data file OUTSIDE the document root - it holds the project secrets.
require_once __DIR__ . '/../src/LicenseServer.php';

$data = getenv('PYP_SERVER_DATA') ?: __DIR__ . '/../pyp.server.json';
$rate = getenv('PYP_RATE_LIMIT');
(new Pyp\LicenseServer($data, $rate === false ? 120 : (int)$rate))->serve();
