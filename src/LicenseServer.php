<?php
declare(strict_types=1);

namespace Pyp;

require_once __DIR__ . '/../loader/pyp-loader.php';

/**
 * Reference implementation of the license endpoint (see docs/license-protocol.md).
 * Storage is a single JSON file guarded by flock; swap load()/save() for a database in production.
 *
 * Data file layout:
 *   { "projects": { "<id>": {"secret": b64, "sign_secret": b64, "name": "..."} },
 *     "licenses": { "<KEY>": {"project": id, "id": "lic_..", "expires_at": ISO|null,
 *                             "domains": [], "ips": [], "macs": [], "revoked": false,
 *                             "message": null, "ttl": 3600, "note": ""} } }
 */
final class LicenseServer
{
    private const MAX_BODY = 16384;

    public function __construct(private string $dataFile, private int $rateLimit = 120)
    {
    }

    public function load(): array
    {
        $raw = '';
        $fh = @fopen($this->dataFile, 'rb');
        if ($fh) {
            flock($fh, LOCK_SH);
            $raw = (string)stream_get_contents($fh);
            flock($fh, LOCK_UN);
            fclose($fh);
        }
        $d = $raw !== '' ? json_decode($raw, true) : [];
        if (!is_array($d)) {
            throw new \RuntimeException('License data file is corrupt: ' . $this->dataFile);
        }
        return ['projects' => (array)($d['projects'] ?? []), 'licenses' => (array)($d['licenses'] ?? [])];
    }

    /** Read-modify-write under an exclusive lock. */
    public function update(callable $fn): mixed
    {
        $fh = fopen($this->dataFile, 'c+b');
        if (!$fh) {
            throw new \RuntimeException('Cannot open ' . $this->dataFile);
        }
        try {
            flock($fh, LOCK_EX);
            $raw = (string)stream_get_contents($fh);
            $d = $raw !== '' ? json_decode($raw, true) : [];
            if (!is_array($d)) {
                throw new \RuntimeException('License data file is corrupt: ' . $this->dataFile);
            }
            $d = ['projects' => (array)($d['projects'] ?? []), 'licenses' => (array)($d['licenses'] ?? [])];
            $result = $fn($d);
            $json = json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, $json);
            fflush($fh);
            @chmod($this->dataFile, 0600);
            return $result;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    /** Handle one decoded request, return the response array (signed whenever the project is known). */
    public function handle(array $req): array
    {
        $nonce = is_string($req['nonce'] ?? null) && strlen($req['nonce']) <= 64 ? $req['nonce'] : '';
        $base = ['v' => 1, 'nonce' => $nonce, 'issued_at' => gmdate('c'), 'ttl' => 0];
        $projectId = is_string($req['project'] ?? null) ? $req['project'] : '';
        $data = $this->load();
        $project = $data['projects'][$projectId] ?? null;

        if (!is_array($project) || ($req['v'] ?? null) !== 1 || $nonce === '') {
            // cannot sign for an unknown project - the loader rejects unsigned answers as "invalid"
            return $base + ['status' => 'invalid', 'message' => null, 'signature' => ''];
        }

        $key = is_string($req['license'] ?? null) ? Loader::normalizeKey($req['license']) : '';
        $lic = $key !== '' ? ($data['licenses'][$key] ?? null) : null;
        $resp = $base + ['status' => 'ok', 'message' => null, 'license' => null, 'key' => null];

        if (!is_array($lic) || ($lic['project'] ?? null) !== $projectId) {
            $resp['status'] = 'invalid';
        } else {
            $resp['message'] = is_string($lic['message'] ?? null) ? $lic['message'] : null;
            $resp['license'] = [
                'id' => (string)($lic['id'] ?? ''),
                'expires_at' => $lic['expires_at'] ?? null,
                'domains' => array_values((array)($lic['domains'] ?? [])),
                'ips' => array_values((array)($lic['ips'] ?? [])),
                'macs' => array_values((array)($lic['macs'] ?? [])),
            ];
            $host = self::sanitizeHost($req['host'] ?? null);
            if (!empty($lic['revoked'])) {
                $resp['status'] = 'revoked';
            } elseif (($reason = Loader::checkRestrictions($resp['license'], $host)) !== null) {
                $resp['status'] = $reason === 'expired' ? 'expired' : 'not_authorized';
            }
        }

        if ($resp['status'] === 'ok') {
            $resp['ttl'] = max(0, min(604800, (int)($lic['ttl'] ?? 3600)));
            $epk = is_string($req['epk'] ?? null) ? base64_decode($req['epk'], true) : false;
            if ($epk === false || strlen($epk) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
                $resp['status'] = 'invalid';
                $resp['ttl'] = 0;
            } else {
                $share = Loader::projectShare((string)base64_decode((string)$project['secret'], true));
                $resp['key'] = base64_encode(sodium_crypto_box_seal($share, $epk));
            }
        }
        if ($resp['status'] !== 'ok') {
            $resp['key'] = null;
        }

        $resp['signature'] = base64_encode(sodium_crypto_sign_detached(
            Loader::canonical($resp),
            (string)base64_decode((string)$project['sign_secret'], true)
        ));
        return $resp;
    }

    private static function sanitizeHost(mixed $h): array
    {
        $h = is_array($h) ? $h : [];
        $strings = static fn($v): array => array_values(array_filter((array)$v, 'is_string'));
        return [
            'domain' => is_string($h['domain'] ?? null) ? strtolower($h['domain']) : '',
            'ips' => array_slice($strings($h['ips'] ?? []), 0, 32),
            'macs' => array_slice($strings($h['macs'] ?? []), 0, 64),
        ];
    }

    /** HTTP entry point: POST application/json. */
    public function serve(): void
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            http_response_code(405);
            header('Allow: POST');
            echo json_encode(['status' => 'invalid', 'message' => 'POST a JSON request.']);
            return;
        }
        if ($this->rateLimited((string)($_SERVER['REMOTE_ADDR'] ?? ''))) {
            http_response_code(429);
            header('Retry-After: 60');
            echo json_encode(['status' => 'invalid', 'message' => 'Too many requests.']);
            return;
        }
        $body = (string)file_get_contents('php://input', false, null, 0, self::MAX_BODY + 1);
        $req = strlen($body) <= self::MAX_BODY ? json_decode($body, true, 8) : null;
        if (!is_array($req)) {
            http_response_code(400);
            echo json_encode(['status' => 'invalid', 'message' => 'Invalid JSON request.']);
            return;
        }
        try {
            echo json_encode($this->handle($req), JSON_UNESCAPED_SLASHES);
        } catch (\Throwable $e) {
            error_log('pyp license server: ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['status' => 'invalid', 'message' => 'Internal error.']);
        }
    }

    private function rateLimited(string $ip): bool
    {
        if ($this->rateLimit <= 0 || $ip === '') {
            return false;
        }
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pyp-server-rl';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        $file = $dir . DIRECTORY_SEPARATOR . hash('sha256', $ip) . '.json';
        $fh = @fopen($file, 'c+b');
        if (!$fh) {
            return false;
        }
        flock($fh, LOCK_EX);
        $d = json_decode((string)stream_get_contents($fh), true);
        $minute = intdiv(time(), 60);
        if (!is_array($d) || ($d['m'] ?? 0) !== $minute) {
            $d = ['m' => $minute, 'n' => 0];
        }
        $d['n']++;
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, (string)json_encode($d));
        flock($fh, LOCK_UN);
        fclose($fh);
        return $d['n'] > $this->rateLimit;
    }

    /** 125 bit random key: PYP-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (Crockford base32). */
    public static function generateKey(): string
    {
        $alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
        $groups = [];
        for ($g = 0; $g < 5; $g++) {
            $s = '';
            for ($i = 0; $i < 5; $i++) {
                $s .= $alphabet[random_int(0, 31)];
            }
            $groups[] = $s;
        }
        return 'PYP-' . implode('-', $groups);
    }
}
