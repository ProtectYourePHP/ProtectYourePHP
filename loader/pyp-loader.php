<?php
/**
 * ProtectYourePHP loader  -  single file, no dependencies.
 * Runs on PHP 7.4 - 8.5 (ext-sodium, bundled with PHP). Uses the native "pyp"
 * extension for some helpers when it is installed.
 *
 * Ship this directory next to your encoded files (the encoder does that for you):
 *   pyp-loader.php   this file
 *   pyp-config.php   public project settings written by the encoder
 *   activate.php     license activation page (users are redirected here)
 *   license.php      created by the activation page (not web readable)
 *
 * Optional configuration (before the first encoded file is loaded):
 *   \Pyp\Loader::configure([
 *       'license'        => 'PYP-...',            // or env PYP_LICENSE, or license.php
 *       'license_file'   => '/etc/app/pyp-license.php',  // or env PYP_LICENSE_FILE
 *       'domain'         => 'example.com',        // or env PYP_DOMAIN (recommended behind proxies)
 *       'ip'             => '203.0.113.5',        // or env PYP_IP
 *       'cache_dir'      => '/var/cache/pyp',     // or env PYP_CACHE_DIR
 *       'activation_url' => '/pyp/activate.php',  // where unlicensed visitors are sent
 *       'allow_change'   => false,                // allow replacing an active license on activate.php
 *       'on_error'       => function ($type, $message) {},
 *       'throw'          => true,                 // throw \Pyp\LicenseException instead of exiting
 *   ]);
 */

namespace Pyp;

if (\class_exists('Pyp\Loader', false)) {
    return;
}

final class LicenseException extends \RuntimeException
{
    /** @var string missing|expired|unauthorized|unreachable|invalid|key|corrupt|denied */
    public $type = 'invalid';
}

final class Loader
{
    const VERSION = '1.4.0';
    const MAGIC = 'PYP1';
    const MAX_TTL = 604800;
    const MAX_RESPONSE = 65536;
    const MAX_HEADER = 65536;
    const KEY_PATTERN = '/^[A-Z0-9][A-Z0-9-]{7,79}$/';
    const LICENSE_GUARD = "<?php http_response_code(404); exit; ?>\n";

    const DEFAULT_MESSAGES = [
        'missing'      => 'No license key has been entered for this installation.',
        'expired'      => 'This software license has expired.',
        'unauthorized' => 'This software is not licensed for this server.',
        'unreachable'  => 'The license server could not be reached.',
        'invalid'      => 'The license is invalid.',
        'key'          => 'A required decryption key is missing.',
        'corrupt'      => 'This protected file is corrupt or has been modified.',
        'denied'       => 'Access to this protected file was denied.',
        'extension'    => 'This protected file requires the PYP PHP extension (pyp).',
        'updates'      => 'This version was released after the update period of your license ended. Please enter a license with a longer update period.',
    ];

    /** @var array */
    private static $config = [];
    /** @var array<string,string> real path => decrypted source waiting for its include */
    private static $pending = [];
    /** @var array<string,array> */
    private static $grants = [];
    /** @var bool */
    private static $registered = false;
    /** @var string[]|null */
    private static $macs = null;
    /** @var array|null */
    private static $site = null;

    public static function configure(array $config): void
    {
        self::$config = array_merge(self::$config, $config);
        if (array_key_exists('license', $config)) {
            self::$grants = [];
        }
    }

    // ==================================================================
    // Runtime API
    // ==================================================================

    /**
     * Called by the stub of every encoded PHP file:  return include \Pyp\Loader::open(__FILE__);
     * Only the encoded file itself may call this for itself.
     */
    public static function open(string $file): string
    {
        $real = self::realPath($file);
        $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 1);
        $caller = isset($bt[0]['file']) ? self::realPath((string)$bt[0]['file']) : '';
        if (!self::samePath($caller, $real)) {
            self::fail('denied', [], null);
            throw self::exception('denied', null);
        }
        $plain = self::decryptFile($real, 'php');
        self::register();
        self::$pending[$real] = $plain;
        return 'pyp://' . $real;
    }

    /** Decrypt a protected data file (XML, templates, ...). Protected PHP code cannot be read. */
    public static function read(string $path): string
    {
        return self::decryptFile(self::realPath($path), 'data');
    }

    /** Replacement for __FILE__ inside encoded code. */
    public static function file(string $path): string
    {
        return strncmp($path, 'pyp://', 6) === 0 ? substr($path, 6) : $path;
    }

    /** Replacement for __DIR__ inside encoded code. */
    public static function dir(string $path): string
    {
        return dirname(self::file($path));
    }

    public static function register(): void
    {
        if (!self::$registered) {
            if (in_array('pyp', stream_get_wrappers(), true)) {
                stream_wrapper_unregister('pyp');
            }
            stream_wrapper_register('pyp', StreamWrapper::class);
            self::$registered = true;
        }
    }

    /** @internal used by the stream wrapper */
    public static function takePending(string $real): ?string
    {
        if (!isset(self::$pending[$real])) {
            return null;
        }
        $s = self::$pending[$real];
        unset(self::$pending[$real]);
        return $s;
    }

    /** @internal used by the stream wrapper: 'php', 'data' or null for plain files */
    public static function peekKind(string $file): ?string
    {
        $fh = @fopen($file, 'rb');
        if (!$fh) {
            return null;
        }
        $kind = null;
        $stat = fstat($fh);
        $size = $stat ? (int)$stat['size'] : 0;
        if ($size >= 12 && fseek($fh, -4, SEEK_END) === 0) {
            $t = fread($fh, 4);
            $len = strlen((string)$t) === 4 ? unpack('N', $t)[1] : 0;
            if ($len >= 8 && $len <= $size - 4 && fseek($fh, $size - 4 - $len) === 0) {
                $head = (string)fread($fh, 8);
                if (strlen($head) === 8 && substr($head, 0, 4) === self::MAGIC) {
                    $hl = unpack('N', substr($head, 4))[1];
                    if ($hl > 0 && $hl <= self::MAX_HEADER && $hl < $len) {
                        $h = json_decode((string)fread($fh, $hl), true);
                        $kind = is_array($h) && in_array($h['kind'] ?? null, ['php', 'data'], true) ? $h['kind'] : 'corrupt';
                    }
                }
            }
        }
        fclose($fh);
        return $kind;
    }

    /** @internal used by the stream wrapper */
    public static function decryptForWrapper(string $file, string $kind): string
    {
        return self::decryptFile($file, $kind);
    }

    // ==================================================================
    // Container format  (shared with the encoder)
    // MAGIC | u32 headerLen | header(JSON) | ciphertext | u32 totalLenBefore
    // ==================================================================

    public static function pack(string $headerJson, string $cipher): string
    {
        $body = self::MAGIC . pack('N', strlen($headerJson)) . $headerJson . $cipher;
        return $body . pack('N', strlen($body));
    }

    /** @return array{0:array,1:string,2:string} header, cipher, raw header (AAD) */
    private static function parseContainer(string $file): array
    {
        $fh = @fopen($file, 'rb');
        if (!$fh) {
            throw self::exception('corrupt', null);
        }
        try {
            $stat = fstat($fh);
            $size = $stat ? (int)$stat['size'] : 0;
            if ($size < 12 || fseek($fh, -4, SEEK_END) !== 0) {
                throw self::exception('corrupt', null);
            }
            $t = (string)fread($fh, 4);
            $len = strlen($t) === 4 ? unpack('N', $t)[1] : 0;
            if ($len < 8 || $len > $size - 4 || fseek($fh, $size - 4 - $len) !== 0) {
                throw self::exception('corrupt', null);
            }
            $blob = (string)fread($fh, $len);
        } finally {
            fclose($fh);
        }
        if (strlen($blob) !== $len || substr($blob, 0, 4) !== self::MAGIC) {
            throw self::exception('corrupt', null);
        }
        $hl = unpack('N', substr($blob, 4, 4))[1];
        if ($hl < 2 || $hl > self::MAX_HEADER || 8 + $hl > $len) {
            throw self::exception('corrupt', null);
        }
        $raw = substr($blob, 8, $hl);
        $header = json_decode($raw, true, 16);
        if (!is_array($header) || !self::validHeader($header)) {
            throw self::exception('corrupt', null);
        }
        return [$header, substr($blob, 8 + $hl), $raw];
    }

    private static function validHeader(array $h): bool
    {
        $b = static function ($v, int $len): bool {
            $d = is_string($v) ? base64_decode($v, true) : false;
            return $d !== false && strlen($d) === $len;
        };
        $l = $h['layers'] ?? null;
        if (($h['v'] ?? null) !== 1 || !is_string($h['project'] ?? null)
            || !is_string($h['file'] ?? null) || !preg_match('/^[0-9a-f]{16}$/', $h['file'])
            || !in_array($h['kind'] ?? null, ['php', 'data'], true)
            || !$b($h['salt'] ?? null, 32) || !$b($h['nonce'] ?? null, 24)
            || !is_array($l) || !$b($l['embedded'] ?? null, 32)) {
            return false;
        }
        if (!empty($l['external'])) {
            $e = $l['external'];
            if (!is_array($e) || !in_array($e['type'] ?? null, ['file', 'env'], true) || !is_string($e['ref'] ?? null)) {
                return false;
            }
        }
        if (!empty($l['server'])) {
            $s = $l['server'];
            if (!is_array($s) || !is_string($s['url'] ?? null) || !$b($s['pk'] ?? null, 32)) {
                return false;
            }
        }
        if (isset($h['built']) && (!is_int($h['built']) || $h['built'] < 0)) {
            return false;
        }
        if (isset($h['loader']) && (!is_string($h['loader']) || !preg_match('#^(\.\./)*[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$#', $h['loader']))) {
            return false;
        }
        return true;
    }

    // ==================================================================
    // Crypto helpers (shared with the encoder & reference server)
    // ==================================================================

    public static function deriveKey(string $embedded, ?string $external, ?string $share, string $fileId, string $salt): string
    {
        $lp = static function (string $s): string {
            return pack('N', strlen($s)) . $s;
        };
        $ikm = $lp($embedded) . $lp($external ?? '') . $lp($share ?? '');
        return hash_hkdf('sha256', $ikm, 32, 'pyp1|' . $fileId, $salt);
    }

    public static function externalBytes(string $secret): string
    {
        return hash('sha256', trim($secret), true);
    }

    /** The per-project key share the license server hands out after a successful check. */
    public static function projectShare(string $projectSecret): string
    {
        return hash_hmac('sha256', 'pyp-share-v1', $projectSecret, true);
    }

    /** Canonical JSON used for response signatures: keys sorted recursively, unescaped slashes/unicode. */
    public static function canonical($value): string
    {
        $sort = static function ($v) use (&$sort) {
            if (!is_array($v)) {
                return $v;
            }
            $isList = $v === [] || array_keys($v) === range(0, count($v) - 1);
            if (!$isList) {
                ksort($v, SORT_STRING);
            }
            foreach ($v as $k => $x) {
                $v[$k] = $sort($x);
            }
            return $v;
        };
        return json_encode($sort($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    public static function normalizeKey(string $key): string
    {
        return strtoupper((string)preg_replace('/\s+/', '', $key));
    }

    // ==================================================================
    // Decryption / key resolution
    // ==================================================================

    private static function decryptFile(string $file, string $kind): string
    {
        $header = [];
        try {
            [$header, $cipher, $raw] = self::parseContainer($file);
            if ($header['kind'] !== $kind) {
                throw self::exception($kind === 'data' ? 'denied' : 'corrupt', null);
            }
            if ($kind === 'php' && !empty($header['ext'])) {
                // built with --require-ext: only the native extension hands this code to the compiler
                throw self::exception('extension', null);
            }
            $key = self::resolveKey($header);
            try {
                $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                    $cipher,
                    $raw,
                    (string)base64_decode((string)$header['nonce'], true),
                    $key
                );
            } catch (\SodiumException $e) {
                $plain = false;
            }
            if (function_exists('sodium_memzero')) {
                sodium_memzero($key);
            }
            if ($plain === false) {
                throw self::exception('corrupt', null);
            }
            return $plain;
        } catch (LicenseException $e) {
            self::fail($e->type, $header, $e->getMessage() !== '' ? $e->getMessage() : null);
            throw $e;
        }
    }

    // ==================================================================
    // Native extension (files built with --require-ext)
    // The extension's compile hook asks for the file key, decrypts in C and hands the source
    // straight to the compiler. Licensing still happens here (loader API 2).
    // ==================================================================

    /** @var array|null [type, header, message] of the last refused --require-ext file */
    private static $extError = null;

    /**
     * @internal called by the native extension: file key (32 bytes) + nonce (24 bytes),
     * or null when the file may not run (the reason is reported by extFail()).
     */
    public static function extKey(string $file): ?string
    {
        $header = [];
        try {
            [$header] = self::parseContainer(self::realPath($file));
            if ($header['kind'] !== 'php' || empty($header['ext'])) {
                throw self::exception('corrupt', null);
            }
            return self::resolveKey($header) . (string)base64_decode((string)$header['nonce'], true);
        } catch (LicenseException $e) {
            self::$extError = [$e->type, $header, $e->getMessage() !== '' ? $e->getMessage() : null];
            return null;
        }
    }

    /** @internal called by the native extension when decryption failed */
    public static function extReject(string $type): void
    {
        self::$extError = [isset(self::DEFAULT_MESSAGES[$type]) ? $type : 'corrupt', [], null];
    }

    /** @internal the extension compiles a call to this in place of a refused file */
    public static function extFail(): void
    {
        [$type, $header, $message] = self::$extError ?? ['corrupt', [], null];
        self::fail($type, $header, $message);
        throw self::exception($type, $message);
    }

    private static function resolveKey(array $header): string
    {
        $layers = $header['layers'];
        $external = null;
        if (!empty($layers['external'])) {
            $ref = $layers['external'];
            $secret = false;
            if ($ref['ref'] !== '') {
                $secret = $ref['type'] === 'env' ? getenv($ref['ref']) : @file_get_contents($ref['ref']);
            }
            if (!is_string($secret) || trim($secret) === '') {
                throw self::exception('key', null);
            }
            $external = self::externalBytes($secret);
        }
        $share = null;
        if (!empty($layers['server'])) {
            $license = self::findLicense($layers['server']);
            if ($license === '') {
                throw self::exception('missing', null);
            }
            $grant = self::share($header['project'], $layers['server'], $license, (int)($header['grace'] ?? 0), false);
            self::checkUpdatePeriod($header, $grant['license'], $layers['server'], $license);
            $share = $grant['share'];
        }
        return self::deriveKey(
            (string)base64_decode($layers['embedded'], true),
            $external,
            $share,
            $header['file'],
            (string)base64_decode($header['salt'], true)
        );
    }

    // ==================================================================
    // License handling
    // ==================================================================

    /**
     * Obtain the key share for a project/license (memory -> signed cache -> server).
     * @internal also used by the activation page
     * @return array{share:string,license:array}
     */
    public static function share(string $project, array $srv, string $license, int $grace, bool $fresh): array
    {
        $id = hash('sha256', $project . "\0" . $license . "\0" . (string)$srv['url']);
        $host = self::hostInfo();
        // long-running processes (workers, daemons) must re-validate too: memory grants expire
        if (!$fresh && isset(self::$grants[$id]) && self::$grants[$id]['until'] > time()) {
            return self::accept(self::$grants[$id], $host, $id);
        }
        $dir = self::cacheDir();
        $cacheFile = $dir !== null ? $dir . '/s-' . $id . '.json' : null;
        $negFile = $dir !== null ? self::negFile($dir, $id, $host) : null;

        $stale = null;
        $cached = null;
        if (!$fresh && $cacheFile !== null) {
            $cached = $c = self::loadCachedGrant($cacheFile, $srv, max(0, $grace));
            if ($c !== null && $c['fresh']) {
                return self::accept($c, $host, $id);
            }
            if ($c !== null && $c['in_grace']) {
                $stale = $c;
            }
            $neg = self::readJson((string)$negFile);
            if ($neg !== null && (int)($neg['until'] ?? 0) > time() && is_string($neg['type'] ?? null)) {
                if ($stale !== null && $neg['type'] === 'unreachable') {
                    return self::accept($stale, $host, $id);
                }
                throw self::exception($neg['type'], is_string($neg['message'] ?? null) ? $neg['message'] : null);
            }
        }

        // When the ttl ends, every PHP worker wants a new grant at once. If another process is
        // already refreshing, a still usable (grace) grant is used instead of queueing up.
        $lock = null;
        if ($stale !== null && $dir !== null) {
            $lock = @fopen($dir . '/l-' . $id . '.lock', 'c');
            if ($lock && !@flock($lock, LOCK_EX | LOCK_NB)) {
                fclose($lock);
                return self::accept($stale, $host, $id);
            }
        }
        try {
            $grant = self::requestGrant($project, $srv, $license, $host);
        } catch (LicenseException $e) {
            if ($lock) {
                fclose($lock);
                $lock = null;
            }
            if ($e->type === 'unreachable' && $stale !== null) {
                return self::accept($stale, $host, $id);
            }
            if ($negFile !== null) {
                self::writeJson($negFile, [
                    'type' => $e->type,
                    'message' => $e->getMessage() !== '' ? $e->getMessage() : null,
                    'until' => time() + ($e->type === 'unreachable' ? 30 : 60),
                ]);
            }
            // A refusal for this host (e.g. a cron job reporting another domain) says nothing about
            // a grant that was issued for a different host: only drop a grant this host could use.
            if ($cacheFile !== null && $e->type !== 'unreachable'
                && ($cached === null || self::checkRestrictions($cached['license'], $host) === null)) {
                @unlink($cacheFile);
            }
            throw $e;
        }
        if ($cacheFile !== null) {
            self::writeJson($cacheFile, ['resp' => $grant['resp'], 'sk' => base64_encode($grant['kp']), 'fetched' => time()]);
            @unlink((string)$negFile);
        }
        if ($lock) {
            fclose($lock);
        }
        return self::accept($grant, $host, $id);
    }

    private static function accept(array $grant, array $host, string $id): array
    {
        $reason = self::checkRestrictions($grant['license'], $host);
        if ($reason !== null) {
            throw self::exception($reason === 'expired' ? 'expired' : 'unauthorized', null);
        }
        // kept in memory for at least a minute, so a ttl of 0 does not mean one request per file
        $grant['until'] = max((int)($grant['until'] ?? 0), time() + 60);
        self::$grants[$id] = $grant;
        return ['share' => $grant['share'], 'license' => $grant['license']];
    }

    /**
     * Failures are remembered per host (domain, addresses, path): a refused check from one
     * context (CLI, another virtual host) must not lock out a context that is licensed.
     */
    private static function negFile(string $dir, string $id, array $host): string
    {
        $ctx = [$host['domain'] ?? '', $host['ips'] ?? [], $host['macs'] ?? [], $host['path'] ?? ''];
        return $dir . '/n-' . hash('sha256', $id . "\0" . json_encode($ctx)) . '.json';
    }

    /** @return array{share:string,license:array,resp:array,kp:string} */
    private static function requestGrant(string $project, array $srv, string $license, array $host): array
    {
        $nonce = base64_encode(random_bytes(16));
        $kp = sodium_crypto_box_keypair();
        $request = [
            'v'       => 1,
            'project' => $project,
            'license' => $license,
            'nonce'   => $nonce,
            'epk'     => base64_encode(sodium_crypto_box_publickey($kp)),
            'host'    => $host,
            'php'     => PHP_VERSION,
            'loader'  => self::VERSION,
        ];
        $body = self::httpPost((string)$srv['url'], (string)json_encode($request, JSON_UNESCAPED_SLASHES));
        $resp = $body === null ? null : json_decode($body, true, 16);
        if (!is_array($resp)) {
            throw self::exception('unreachable', null);
        }
        // Not a signed answer to this request: a rate limit (429), proxy/WAF error page, captive
        // portal or a misconfigured URL. That is no statement about the license, so it is handled
        // like an unreachable server (a cached grant stays usable within ttl + grace).
        if (!self::verifySigned($resp, (string)$srv['pk']) || ($resp['nonce'] ?? null) !== $nonce || ($resp['v'] ?? null) !== 1) {
            throw self::exception('unreachable', null);
        }
        $status = (string)($resp['status'] ?? 'invalid');
        $msg = isset($resp['message']) && is_string($resp['message']) && $resp['message'] !== '' ? $resp['message'] : null;
        if ($status !== 'ok') {
            $map = ['expired' => 'expired', 'not_authorized' => 'unauthorized', 'revoked' => 'unauthorized'];
            throw self::exception($map[$status] ?? 'invalid', $msg);
        }
        $share = self::unseal($resp, $kp);
        if ($share === null) {
            throw self::exception('invalid', null);
        }
        return ['share' => $share, 'license' => is_array($resp['license'] ?? null) ? $resp['license'] : [], 'resp' => $resp, 'kp' => $kp,
            'until' => time() + max(0, min(self::MAX_TTL, (int)($resp['ttl'] ?? 0)))];
    }

    private static function verifySigned(array $resp, string $pkB64): bool
    {
        $sig = base64_decode((string)($resp['signature'] ?? ''), true);
        $pk = base64_decode($pkB64, true);
        if ($sig === false || $pk === false || strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        unset($resp['signature']);
        try {
            return sodium_crypto_sign_verify_detached($sig, self::canonical($resp), $pk);
        } catch (\Throwable $e) {
            return false;
        }
    }

    private static function unseal(array $resp, string $kp): ?string
    {
        $sealed = base64_decode((string)($resp['key'] ?? ''), true);
        if ($sealed === false || $sealed === '') {
            return null;
        }
        try {
            $share = sodium_crypto_box_seal_open($sealed, $kp);
        } catch (\SodiumException $e) {
            return null;
        }
        return is_string($share) && strlen($share) === 32 ? $share : null;
    }

    /**
     * The cache holds the complete signed server response, so expiry and restrictions
     * cannot be extended by editing the cache file.
     */
    private static function loadCachedGrant(string $file, array $srv, int $grace): ?array
    {
        $c = self::readJson($file);
        if ($c === null || !is_array($c['resp'] ?? null) || !is_string($c['sk'] ?? null)) {
            return null;
        }
        $resp = $c['resp'];
        if (($resp['status'] ?? null) !== 'ok' || !self::verifySigned($resp, (string)$srv['pk'])) {
            return null;
        }
        $kp = base64_decode($c['sk'], true);
        $issued = strtotime((string)($resp['issued_at'] ?? ''));
        if ($kp === false || $issued === false) {
            return null;
        }
        $share = self::unseal($resp, $kp);
        if ($share === null) {
            return null;
        }
        // never later than the signed issue time (local clock may only shorten the lifetime)
        $start = min($issued, (int)($c['fetched'] ?? $issued));
        $expires = $start + max(0, min(self::MAX_TTL, (int)($resp['ttl'] ?? 0)));
        return [
            'share' => $share,
            'license' => is_array($resp['license'] ?? null) ? $resp['license'] : [],
            'fresh' => $expires > time(),
            'in_grace' => $expires + $grace > time(),
            'until' => $expires,
        ];
    }

    /**
     * Current license state for the activation page.
     * @internal
     * @return array{ok:bool,type:?string,message:?string,license:?array,key:string}
     */
    public static function licenseState(string $project, array $srv): array
    {
        $key = self::findLicense($srv);
        if ($key === '') {
            return ['ok' => false, 'type' => 'missing', 'message' => null, 'license' => null, 'key' => ''];
        }
        try {
            $g = self::share($project, $srv, $key, 0, false);
        } catch (LicenseException $e) {
            return ['ok' => false, 'type' => $e->type, 'message' => $e->getMessage() ?: null, 'license' => null, 'key' => $key];
        }
        // a protected file of this installation was refused because it is newer than the update period
        $marker = self::readJson((string)self::updatesMarker($project, $srv, $key));
        $until = !empty($g['license']['updates_until']) ? strtotime((string)$g['license']['updates_until']) : false;
        if ($marker !== null && $until !== false && (int)($marker['built'] ?? 0) > $until) {
            return ['ok' => false, 'type' => 'updates', 'message' => null, 'license' => $g['license'], 'key' => $key];
        }
        return ['ok' => true, 'type' => null, 'message' => null, 'license' => $g['license'], 'key' => $key];
    }

    /**
     * License of the running application, e.g. to show "support until" or the license type:
     *   $l = \Pyp\Loader::license();
     *   if ($l && $l['support_until'] && strtotime($l['support_until']) > time()) { ... }
     * Returns null when the application does not use online licensing.
     *
     * @return array{valid:bool,error:?string,id:?string,type:?string,expires_at:?string,support_until:?string,updates_until:?string,domains:array,ips:array,macs:array,paths:array}|null
     */
    public static function license(): ?array
    {
        $site = self::site();
        if (!is_array($site['server'] ?? null) || !is_string($site['project'] ?? null)) {
            return null;
        }
        $s = self::licenseState($site['project'], $site['server']);
        $l = is_array($s['license']) ? $s['license'] : [];
        $str = static function ($v): ?string {
            return is_string($v) && $v !== '' ? $v : null;
        };
        return [
            'valid' => $s['ok'],
            'error' => $s['type'],
            'id' => $str($l['id'] ?? null),
            'type' => $str($l['type'] ?? null),
            'expires_at' => $str($l['expires_at'] ?? null),
            'support_until' => $str($l['support_until'] ?? null),
            'updates_until' => $str($l['updates_until'] ?? null),
            'domains' => (array)($l['domains'] ?? []),
            'ips' => (array)($l['ips'] ?? []),
            'macs' => (array)($l['macs'] ?? []),
            'paths' => (array)($l['paths'] ?? []),
        ];
    }

    /** Files built after the license's update period ("updates_until") are refused. */
    private static function checkUpdatePeriod(array $header, array $license, array $srv, string $key): void
    {
        if (empty($license['updates_until']) || !isset($header['built'])) {
            return;
        }
        $until = strtotime((string)$license['updates_until']);
        if ($until !== false && $header['built'] > $until) {
            $marker = self::updatesMarker($header['project'], $srv, $key);
            if ($marker !== null) {
                self::writeJson($marker, ['built' => $header['built']]);
            }
            throw self::exception('updates', null);
        }
    }

    private static function updatesMarker(string $project, array $srv, string $key): ?string
    {
        $dir = self::cacheDir();
        return $dir === null ? null
            : $dir . '/u-' . hash('sha256', $project . "\0" . self::normalizeKey($key) . "\0" . (string)$srv['url']) . '.json';
    }

    private static function findLicense(array $srv): string
    {
        $candidates = [
            self::$config['license'] ?? null,
            getenv('PYP_LICENSE') ?: null,
            self::readLicenseFile(),
            $srv['license'] ?? null,
        ];
        foreach ($candidates as $k) {
            if (is_string($k)) {
                $k = self::normalizeKey($k);
                if (preg_match(self::KEY_PATTERN, $k)) {
                    return $k;
                }
            }
        }
        return '';
    }

    /** @internal */
    public static function licenseFile(): string
    {
        $f = self::$config['license_file'] ?? (getenv('PYP_LICENSE_FILE') ?: (self::site()['license_file'] ?? null));
        return is_string($f) && $f !== '' ? $f : __DIR__ . DIRECTORY_SEPARATOR . 'license.php';
    }

    private static function readLicenseFile(): ?string
    {
        $raw = @file_get_contents(self::licenseFile());
        if (!is_string($raw)) {
            return null;
        }
        if (strncmp($raw, '<?php', 5) === 0) {
            $p = strpos($raw, '?>');
            $raw = $p === false ? '' : substr($raw, $p + 2);
        }
        return trim($raw);
    }

    /** Store a license key in the license file (PHP guard prevents it being served). @internal */
    public static function storeLicense(string $key): bool
    {
        $file = self::licenseFile();
        $dir = dirname($file);
        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }
        $tmp = $dir . DIRECTORY_SEPARATOR . '.license-' . bin2hex(random_bytes(6)) . '.tmp';
        if (@file_put_contents($tmp, self::LICENSE_GUARD . self::normalizeKey($key) . "\n", LOCK_EX) === false) {
            return false;
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $file)) {
            @unlink($file);
            if (!@rename($tmp, $file)) {
                @unlink($tmp);
                return false;
            }
        }
        self::$grants = [];
        return true;
    }

    /** Forget cached grants/failures for a license (after activation). @internal */
    public static function forget(string $project, array $srv, string $license): void
    {
        $id = hash('sha256', $project . "\0" . self::normalizeKey($license) . "\0" . (string)$srv['url']);
        unset(self::$grants[$id]);
        $dir = self::cacheDir();
        if ($dir !== null) {
            @unlink(self::negFile($dir, $id, self::hostInfo()));
        }
    }

    private static function httpPost(string $url, string $json): ?string
    {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'https' && $scheme !== 'http') {
            return null;
        }
        if (function_exists('curl_init')) {
            $buf = '';
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $json,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_WRITEFUNCTION  => static function ($ch, $chunk) use (&$buf) {
                    if (strlen($buf) + strlen($chunk) > self::MAX_RESPONSE) {
                        return 0;
                    }
                    $buf .= $chunk;
                    return strlen($chunk);
                },
            ]);
            $ok = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            return $ok !== false && $code > 0 && $code < 500 ? $buf : null;
        }
        $ctx = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => "Content-Type: application/json\r\nAccept: application/json\r\n",
                'content'       => $json,
                'timeout'       => 10,
                'ignore_errors' => true,
                'follow_location' => 0,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $out = @file_get_contents($url, false, $ctx, 0, self::MAX_RESPONSE);
        return is_string($out) ? $out : null;
    }

    // ==================================================================
    // Cache helpers
    // ==================================================================

    /** @internal */
    public static function cacheDir(): ?string
    {
        static $dir = false;
        if ($dir !== false && !isset(self::$config['cache_dir'])) {
            return $dir;
        }
        $base = self::$config['cache_dir'] ?? (getenv('PYP_CACHE_DIR') ?: null);
        if (!is_string($base) || $base === '') {
            $who = function_exists('posix_geteuid') ? (string)posix_geteuid() : (string)get_current_user();
            $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pyp-cache-' . substr(hash('sha256', $who . '|' . __DIR__), 0, 16);
        }
        // all checks silenced: under open_basedir they warn instead of returning false
        if (!@is_dir($base)) {
            @mkdir($base, 0700, true);
        }
        $ok = @is_dir($base) && !@is_link($base) && @is_writable($base);
        if ($ok && function_exists('posix_geteuid')) {
            $ok = @fileowner($base) === posix_geteuid();   // refuse directories planted by other users
        }
        return $dir = $ok ? rtrim($base, '\\/') : null;
    }

    private static function readJson(string $file): ?array
    {
        if ($file === '') {
            return null;
        }
        $raw = @file_get_contents($file);
        $d = is_string($raw) && strlen($raw) < 1048576 ? json_decode($raw, true, 16) : null;
        return is_array($d) ? $d : null;
    }

    private static function writeJson(string $file, array $data): void
    {
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) {
            @chmod($tmp, 0600);
            if (!@rename($tmp, $file)) {
                @unlink($file);
                @rename($tmp, $file) || @unlink($tmp);
            }
        }
    }

    /** Simple fixed window rate limiter. @internal */
    public static function rateLimited(string $bucket, string $who, int $max, int $window): bool
    {
        $dir = self::cacheDir();
        if ($dir === null) {
            return false;
        }
        $file = $dir . '/r-' . hash('sha256', $bucket . '|' . $who) . '.json';
        $d = self::readJson($file);
        $now = time();
        if ($d === null || (int)($d['start'] ?? 0) + $window <= $now) {
            $d = ['start' => $now, 'n' => 0];
        }
        $d['n'] = (int)$d['n'] + 1;
        self::writeJson($file, $d);
        return $d['n'] > $max;
    }

    // ==================================================================
    // Host info and restriction checks (shared with the reference server)
    // ==================================================================

    public static function hostInfo(): array
    {
        $domain = self::$config['domain'] ?? (getenv('PYP_DOMAIN') ?: null);
        if (!is_string($domain) || $domain === '') {
            // nginx reports "_" (catch-all) or the regex itself for "server_name ~..." vhosts
            $sn = $_SERVER['SERVER_NAME'] ?? '';
            $domain = is_string($sn) && $sn !== '' && $sn !== '_' && $sn[0] !== '~'
                ? $sn : ($_SERVER['HTTP_HOST'] ?? (string)gethostname());
        }
        $cli = PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg';
        if ($cli && !isset(self::$config['domain']) && !getenv('PYP_DOMAIN')) {
            $domain = '';   // no request, so no domain: the machine's hostname says nothing about the site
        }
        $domain = rtrim(strtolower((string)preg_replace('/:\d+$/', '', (string)$domain)), '.');
        if (!preg_match('/^(\[[0-9a-f:.]+\]|[a-z0-9._-]{1,253})$/', $domain)) {
            $domain = '';
        }
        $ips = [];
        foreach ([self::$config['ip'] ?? null, getenv('PYP_IP') ?: null, $_SERVER['SERVER_ADDR'] ?? null] as $ip) {
            if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            }
        }
        $h = (string)gethostname();
        if ($h !== '' && !$ips) {
            $r = @gethostbyname($h);
            if ($r !== $h && filter_var($r, FILTER_VALIDATE_IP)) {
                $ips[] = $r;
            }
        }
        return [
            'domain'   => $domain,
            'hostname' => $h,
            'ips'      => array_values(array_unique($ips)),
            'macs'     => self::macs(),
            'path'     => self::installPath(),
            'sapi'     => PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' ? 'cli' : 'web',
        ];
    }

    /** Installation directory = the directory that contains the loader directory (pyp/). */
    public static function installPath(): string
    {
        $p = self::$config['path'] ?? (getenv('PYP_PATH') ?: null);
        if (!is_string($p) || $p === '') {
            $real = @realpath(dirname(__DIR__));
            $p = $real !== false ? $real : dirname(__DIR__);
        }
        return self::normalizePath($p);
    }

    public static function normalizePath(string $p): string
    {
        $p = rtrim(str_replace('\\', '/', $p), '/');
        return $p === '' ? '/' : $p;
    }

    /** "/var/www/shop" matches exactly, "/var/www/*" matches everything below /var/www. */
    private static function pathMatches(string $path, string $rule): bool
    {
        $path = self::normalizePath($path);
        $rule = self::normalizePath($rule);
        $ci = (bool)preg_match('#^[a-z]:/#i', $path);   // Windows paths are case-insensitive
        if ($ci) {
            $path = strtolower($path);
            $rule = strtolower($rule);
        }
        if (substr($rule, -2) === '/*') {
            $base = substr($rule, 0, -2);
            return $path === $base || strncmp($path, $base . '/', strlen($base) + 1) === 0;
        }
        return $path === $rule;
    }

    /**
     * MAC detection is best effort: hosting restrictions (open_basedir, disabled functions)
     * must never break the loader, they only mean "no MAC addresses known".
     * @return string[] lower-case, colon separated
     */
    private static function macs(): array
    {
        if (self::$macs !== null) {
            return self::$macs;
        }
        try {
            return self::$macs = self::detectMacs();
        } catch (\Throwable $e) {
            return self::$macs = [];
        }
    }

    /** @return string[] */
    private static function detectMacs(): array
    {
        $found = [];
        if (function_exists('pyp_macs')) {
            $found = (array)\pyp_macs();   // native extension
        } else {
            if (function_exists('net_get_interfaces')) {
                foreach ((array)@net_get_interfaces() as $if) {
                    if (is_array($if) && isset($if['mac']) && is_string($if['mac'])) {
                        $found[] = $if['mac'];
                    }
                }
            }
            if (!$found) {
                // glob() returns false (not []) when open_basedir excludes /sys (e.g. Plesk)
                $files = @glob('/sys/class/net/*/address');
                foreach (is_array($files) ? $files : [] as $f) {
                    $content = is_string($f) && $f !== '' ? @file_get_contents($f) : false;
                    if (is_string($content)) {
                        $found[] = $content;
                    }
                }
            }
            $disabled = array_map('trim', explode(',', strtolower((string)ini_get('disable_functions'))));
            if (!$found && function_exists('exec') && !in_array('exec', $disabled, true)) {
                $cmd = PHP_OS_FAMILY === 'Windows' ? 'getmac /fo csv /nh' : '(ip -o link || ifconfig -a) 2>/dev/null';
                $out = [];
                @exec($cmd, $out);
                $found = $out;
            }
        }
        $macs = [];
        foreach ($found as $line) {
            if (preg_match_all('/(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i', (string)$line, $m)) {
                foreach ($m[0] as $mac) {
                    $mac = strtolower(str_replace('-', ':', $mac));
                    if ($mac !== '00:00:00:00:00:00') {
                        $macs[$mac] = true;
                    }
                }
            }
        }
        return array_keys($macs);
    }

    /** @return string|null null when allowed, otherwise expired|domain|ip|mac|path */
    public static function checkRestrictions(array $lic, array $host): ?string
    {
        if (!empty($lic['expires_at'])) {
            $ts = strtotime((string)$lic['expires_at']);
            if ($ts === false || $ts < time()) {
                return 'expired';
            }
        }
        if (!empty($lic['paths'])) {
            // loaders before 1.2 do not report a path: a path restriction then refuses them
            $p = is_string($host['path'] ?? null) ? $host['path'] : '';
            $ok = false;
            foreach ((array)$lic['paths'] as $rule) {
                if ($p !== '' && is_string($rule) && $rule !== '' && self::pathMatches($p, $rule)) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                return 'path';
            }
        }
        // CLI without a configured domain (cron, artisan) has none to check; set PYP_DOMAIN to enforce it
        $noDomain = ($host['sapi'] ?? 'web') === 'cli' && (string)($host['domain'] ?? '') === '';
        if (!empty($lic['domains']) && !$noDomain) {
            $d = (string)($host['domain'] ?? '');
            $ok = false;
            foreach ((array)$lic['domains'] as $pat) {
                $pat = strtolower((string)$pat);
                if ($d !== '' && ($pat === $d
                    || (strncmp($pat, '*.', 2) === 0 && strlen($d) > strlen($pat) - 1
                        && substr($d, -(strlen($pat) - 1)) === substr($pat, 1)))) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                return 'domain';
            }
        }
        if (!empty($lic['ips'])) {
            $ok = false;
            foreach ((array)($host['ips'] ?? []) as $ip) {
                foreach ((array)$lic['ips'] as $rule) {
                    if (self::ipMatches((string)$ip, (string)$rule)) {
                        $ok = true;
                        break 2;
                    }
                }
            }
            if (!$ok) {
                return 'ip';
            }
        }
        if (!empty($lic['macs'])) {
            $allowed = array_map(static function ($m) {
                return strtolower(str_replace('-', ':', (string)$m));
            }, (array)$lic['macs']);
            if (!array_intersect($allowed, (array)($host['macs'] ?? []))) {
                return 'mac';
            }
        }
        return null;
    }

    private static function ipMatches(string $ip, string $rule): bool
    {
        if (strpos($rule, '/') === false) {
            $a = @inet_pton($ip);
            return $a !== false && $a === @inet_pton($rule);
        }
        [$net, $bits] = explode('/', $rule, 2);
        $a = @inet_pton($ip);
        $b = @inet_pton($net);
        if ($a === false || $b === false || strlen($a) !== strlen($b) || !ctype_digit($bits)) {
            return false;
        }
        $bits = (int)$bits;
        if ($bits > strlen($a) * 8) {
            return false;
        }
        $bytes = intdiv($bits, 8);
        if ($bytes && strncmp($a, $b, $bytes) !== 0) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
    }

    // ==================================================================
    // Site config, paths, errors
    // ==================================================================

    /** Public settings written by the encoder (pyp-config.php next to this file). @internal */
    public static function site(): array
    {
        if (self::$site === null) {
            $f = __DIR__ . DIRECTORY_SEPARATOR . 'pyp-config.php';
            $s = is_file($f) ? (static function ($f) {
                return include $f;
            })($f) : [];
            self::$site = is_array($s) ? $s : [];
        }
        return self::$site;
    }

    /** URL of the activation page, or null when it cannot be determined. @internal */
    public static function activationUrl(): ?string
    {
        $u = self::$config['activation_url'] ?? (self::site()['activation_url'] ?? null);
        if (is_string($u) && $u !== '') {
            return $u;
        }
        $page = realpath(__DIR__ . DIRECTORY_SEPARATOR . 'activate.php');
        $root = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
        if ($page === false || $root === false || $root === '') {
            return null;
        }
        $root = rtrim($root, '\\/') . DIRECTORY_SEPARATOR;
        if (!self::samePath(substr($page, 0, strlen($root)), $root)) {
            return null;
        }
        $rel = str_replace('\\', '/', substr($page, strlen($root)));
        return '/' . implode('/', array_map('rawurlencode', explode('/', $rel)));
    }

    /** @internal */
    public static function isActivationRequest(): bool
    {
        $script = isset($_SERVER['SCRIPT_FILENAME']) ? realpath((string)$_SERVER['SCRIPT_FILENAME']) : false;
        $page = realpath(__DIR__ . DIRECTORY_SEPARATOR . 'activate.php');
        return $script !== false && $page !== false && self::samePath($script, $page);
    }

    /** @internal */
    public static function message(string $type, array $header = []): string
    {
        $m = $header['messages'][$type] ?? (self::site()['messages'][$type] ?? null);
        return is_string($m) && $m !== '' ? $m : (self::DEFAULT_MESSAGES[$type] ?? 'Protected file error.');
    }

    private static function realPath(string $file): string
    {
        $file = self::file($file);
        $r = realpath($file);
        return $r !== false ? $r : $file;
    }

    private static function samePath(string $a, string $b): bool
    {
        return PHP_OS_FAMILY === 'Windows' ? strcasecmp($a, $b) === 0 : $a === $b;
    }

    private static function exception(string $type, ?string $message): LicenseException
    {
        $e = new LicenseException($message ?? '');
        $e->type = $type;
        return $e;
    }

    private static function fail(string $type, array $header, ?string $custom): void
    {
        $text = $custom ?? self::message($type, $header);
        if (isset(self::$config['on_error']) && is_callable(self::$config['on_error'])) {
            (self::$config['on_error'])($type, $text);
        }
        if (!empty(self::$config['throw'])) {
            throw self::exception($type, $text);
        }
        while (PHP_SAPI !== 'cli' && ob_get_level() > 0) {
            @ob_end_clean();
        }
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            fwrite(STDERR, $text . PHP_EOL);
            exit(255);
        }

        $server = $header['layers']['server'] ?? (self::site()['server'] ?? null);
        $licenseProblem = in_array($type, ['missing', 'expired', 'unauthorized', 'invalid', 'updates'], true) && is_array($server);
        if ($licenseProblem && !self::isActivationRequest()) {
            $url = self::activationUrl();
            $return = Activation::safeReturn((string)($_SERVER['REQUEST_URI'] ?? ''));
            $wantsJson = stripos((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json') !== false
                || strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest';
            if ($url !== null) {
                $target = $url . (strpos($url, '?') === false ? '?' : '&')
                    . http_build_query(['reason' => $type, 'return' => $return]);
            }
            if ($wantsJson) {
                if (!headers_sent()) {
                    http_response_code(403);
                    header('Content-Type: application/json');
                    header('Cache-Control: no-store');
                }
                echo json_encode(['error' => $type, 'message' => $text, 'activation_url' => $target ?? null], JSON_UNESCAPED_SLASHES);
                exit(255);
            }
            if (isset($target) && !headers_sent()) {
                http_response_code(302);
                header('Location: ' . $target);
                header('Cache-Control: no-store');
                header('Content-Type: text/html; charset=utf-8');
                $t = htmlspecialchars($target, ENT_QUOTES, 'UTF-8');
                echo "<!doctype html><meta charset=utf-8><title>License required</title><p><a href=\"$t\">Enter a license key</a></p>";
                exit(255);
            }
            // activation page is not reachable via URL: show it in place
            Activation::run([
                'project' => (string)($header['project'] ?? (self::site()['project'] ?? '')),
                'server'  => $server,
                'reason'  => $type,
                'message' => $text,
                'inline'  => true,
            ]);
            exit(255);
        }

        if (!headers_sent()) {
            http_response_code($type === 'unreachable' ? 503 : 403);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo Activation::page('Unavailable', '<p>' . htmlspecialchars($text, ENT_QUOTES, 'UTF-8') . '</p>');
        exit(255);
    }
}

/**
 * License activation page. Used by activate.php and, when that page has no URL,
 * rendered in place of the protected page.
 */
final class Activation
{
    public static function run(array $ctx = []): void
    {
        $site = Loader::site();
        $project = (string)($ctx['project'] ?? ($site['project'] ?? ''));
        $srv = $ctx['server'] ?? ($site['server'] ?? null);
        $inline = !empty($ctx['inline']);
        $product = htmlspecialchars((string)($site['product'] ?? 'this software'), ENT_QUOTES, 'UTF-8');

        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-Frame-Options: DENY');
            header('X-Content-Type-Options: nosniff');
            header('Referrer-Policy: no-referrer');
            header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        }
        if (!is_array($srv) || $project === '') {
            echo self::page('License', '<p>This installation does not use online licensing.</p>');
            return;
        }

        $csrf = (string)($_COOKIE['pyp_csrf'] ?? '');
        if (!preg_match('/^[0-9a-f]{64}$/', $csrf)) {
            $csrf = bin2hex(random_bytes(32));
            if (!headers_sent()) {
                $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (int)($_SERVER['SERVER_PORT'] ?? 0) === 443;
                setcookie('pyp_csrf', $csrf, ['path' => '/', 'httponly' => true, 'samesite' => 'Strict', 'secure' => $https]);
            }
        }
        $return = self::safeReturn((string)($_POST['return'] ?? ($_GET['return'] ?? '')));
        if ($inline) {
            $return = self::safeReturn((string)($_SERVER['REQUEST_URI'] ?? '/'));
        }

        $state = Loader::licenseState($project, $srv);
        $allowChange = !empty($site['allow_change']);
        $error = null;
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'cli');

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['pyp_action'] ?? '') === 'activate') {
            $key = Loader::normalizeKey((string)($_POST['license'] ?? ''));
            if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
                $error = 'Your session has expired. Please try again.';
            } elseif ($state['ok'] && !$allowChange) {
                $error = 'A valid license is already active for this installation.';
            } elseif (Loader::rateLimited('activate', $ip, 10, 900)) {
                $error = 'Too many attempts. Please wait a few minutes.';
            } elseif (!preg_match(Loader::KEY_PATTERN, $key)) {
                $error = 'Please enter a license key in the form PYP-XXXXX-XXXXX-...';
            } else {
                try {
                    Loader::share($project, $srv, $key, 0, true);
                    if (!Loader::storeLicense($key)) {
                        $error = 'The license is valid, but it could not be saved. Make the file '
                            . Loader::licenseFile() . ' writable or set the environment variable PYP_LICENSE.';
                    } else {
                        Loader::forget($project, $srv, $key);
                        $to = $return !== '' ? $return : (Loader::activationUrl() ?? '/');
                        if (!headers_sent()) {
                            http_response_code(303);
                            header('Location: ' . $to);
                        }
                        echo self::page('License activated', '<p>Thank you, the license is active. <a href="'
                            . htmlspecialchars($to, ENT_QUOTES, 'UTF-8') . '">Continue</a></p>');
                        return;
                    }
                } catch (LicenseException $e) {
                    $error = $e->getMessage() !== '' ? $e->getMessage() : Loader::message($e->type);
                }
            }
        }

        $h = static function ($s): string {
            return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
        };
        $body = '';
        if ($state['ok']) {
            $lic = $state['license'] ?? [];
            $body .= '<p class="ok">The license for ' . $product . ' is active.</p><dl>'
                . '<dt>License</dt><dd>' . $h($lic['id'] ?? '-') . '</dd>'
                . '<dt>Key</dt><dd>' . $h(substr($state['key'], 0, 9)) . '&hellip;</dd>'
                . (!empty($lic['type']) ? '<dt>Type</dt><dd>' . $h($lic['type']) . '</dd>' : '')
                . '<dt>Valid until</dt><dd>' . $h(isset($lic['expires_at']) ? substr((string)$lic['expires_at'], 0, 10) : 'unlimited') . '</dd>'
                . (!empty($lic['support_until']) ? '<dt>Support until</dt><dd>' . $h(substr((string)$lic['support_until'], 0, 10)) . '</dd>' : '')
                . (!empty($lic['updates_until']) ? '<dt>Updates until</dt><dd>' . $h(substr((string)$lic['updates_until'], 0, 10)) . '</dd>' : '')
                . '</dl>';
            if ($return !== '') {
                $body .= '<p><a href="' . $h($return) . '">Continue</a></p>';
            }
        } else {
            $reason = (string)($ctx['reason'] ?? ($state['type'] ?? 'missing'));
            $msg = $ctx['message'] ?? ($state['message'] ?? Loader::message($reason));
            $body .= '<p class="warn">' . $h($msg) . '</p>';
        }
        if ($error !== null) {
            $body .= '<p class="err">' . $h($error) . '</p>';
        }
        if (!$state['ok'] || $allowChange) {
            $action = $inline ? $h($_SERVER['REQUEST_URI'] ?? '') : '';
            $body .= '<form method="post" action="' . $action . '" autocomplete="off">'
                . '<label for="pyp-license">License key</label>'
                . '<input id="pyp-license" name="license" required maxlength="80" placeholder="PYP-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" spellcheck="false">'
                . '<input type="hidden" name="csrf" value="' . $h($csrf) . '">'
                . '<input type="hidden" name="return" value="' . $h($return) . '">'
                . '<input type="hidden" name="pyp_action" value="activate">'
                . '<button type="submit">Activate</button></form>';
        }
        if (!$state['ok'] && !headers_sent() && $inline) {
            http_response_code(403);
        }
        echo self::page('Activate ' . $product, $body);
    }

    /** Only local absolute paths are accepted as return targets (no open redirects). */
    public static function safeReturn(string $r): string
    {
        if ($r === '' || strlen($r) > 2000 || $r[0] !== '/' || (isset($r[1]) && ($r[1] === '/' || $r[1] === '\\'))
            || preg_match('/[\x00-\x1f\x7f\\\\]/', $r)) {
            return '';
        }
        return $r;
    }

    public static function page(string $title, string $body): string
    {
        $t = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
        return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<meta name="robots" content="noindex"><title>' . $t . '</title><style>'
            . ':root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#5b6474;--line:#d9dde4;--acc:#2456d6;--err:#b42318;--ok:#067647;--warn:#9a6700}'
            . '@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b1f27;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2e3440;--acc:#7aa2ff;--err:#ff8a80;--ok:#6fdc9b;--warn:#f5c451}}'
            . 'body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}'
            . 'main{max-width:440px;margin:10vh auto;padding:0 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px}'
            . 'h1{font-size:20px;margin:0 0 16px}label{display:block;font-weight:600;margin:16px 0 6px}'
            . 'input[name=license]{box-sizing:border-box;width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:15px ui-monospace,monospace;letter-spacing:.03em}'
            . 'button{margin-top:16px;padding:10px 18px;border:0;border-radius:8px;background:var(--acc);color:#fff;font:inherit;font-weight:600;cursor:pointer}'
            . '.err{color:var(--err)}.ok{color:var(--ok)}.warn{color:var(--warn)}dl{display:grid;grid-template-columns:auto 1fr;gap:4px 16px;color:var(--mut)}dd{margin:0;color:var(--fg)}a{color:var(--acc)}'
            . '</style></head><body><main><div class="card"><h1>' . $t . '</h1>' . $body . '</div></main></body></html>';
    }
}

/**
 * pyp://<absolute path>
 *  - encoded PHP:  served decrypted, but only to include/require (never to fopen, highlight_file, ...)
 *  - encoded data: served decrypted
 *  - anything else and every write: passed through to the real file
 * This keeps __DIR__ based paths working even inside constant expressions.
 * @internal
 */
final class StreamWrapper
{
    /** @var resource|null */
    public $context;
    /** @var string|null */
    private $data = null;
    /** @var int */
    private $pos = 0;
    /** @var resource|null */
    private $fh = null;
    /** @var resource|null */
    private $dh = null;

    private static function real(string $url): string
    {
        return strncmp($url, 'pyp://', 6) === 0 ? substr($url, 6) : $url;
    }

    private static function isInclude(int $options): bool
    {
        if (($options & 128) === 0) {   // STREAM_OPEN_FOR_INCLUDE
            return false;
        }
        $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        $fn = isset($bt[2]['function']) && !isset($bt[2]['class']) ? strtolower((string)$bt[2]['function']) : '';
        return in_array($fn, ['include', 'include_once', 'require', 'require_once'], true);
    }

    public function stream_open($path, $mode, $options, &$opened_path)
    {
        $real = self::real((string)$path);
        if (strpbrk((string)$mode, 'waxc+') === false) {
            $include = self::isInclude((int)$options);
            if ($include) {
                $pending = Loader::takePending($real);
                if ($pending !== null) {
                    $this->data = $pending;
                    return true;
                }
            }
            $kind = Loader::peekKind($real);
            if ($kind === 'php' || $kind === 'corrupt') {
                if (!$include || $kind === 'corrupt') {
                    if ($options & STREAM_REPORT_ERRORS) {
                        trigger_error('Protected PHP files can only be executed', E_USER_WARNING);
                    }
                    return false;
                }
                $this->data = Loader::decryptForWrapper($real, 'php');
                return true;
            }
            if ($kind === 'data') {
                $this->data = Loader::decryptForWrapper($real, 'data');
                return true;
            }
        }
        $fh = $this->context ? @fopen($real, (string)$mode, false, $this->context) : @fopen($real, (string)$mode);
        if (!$fh) {
            return false;
        }
        $this->fh = $fh;
        return true;
    }

    public function stream_read($count)
    {
        if ($this->fh) {
            return fread($this->fh, $count);
        }
        $chunk = (string)substr((string)$this->data, $this->pos, $count);
        $this->pos += strlen($chunk);
        return $chunk;
    }

    public function stream_write($data)
    {
        return $this->fh ? fwrite($this->fh, $data) : 0;
    }

    public function stream_eof()
    {
        return $this->fh ? feof($this->fh) : $this->pos >= strlen((string)$this->data);
    }

    public function stream_tell()
    {
        return $this->fh ? ftell($this->fh) : $this->pos;
    }

    public function stream_seek($offset, $whence)
    {
        if ($this->fh) {
            return fseek($this->fh, $offset, $whence) === 0;
        }
        $len = strlen((string)$this->data);
        $new = $whence === SEEK_SET ? $offset : ($whence === SEEK_CUR ? $this->pos + $offset : $len + $offset);
        if ($new < 0) {
            return false;
        }
        $this->pos = $new;
        return true;
    }

    public function stream_flush()
    {
        return $this->fh ? fflush($this->fh) : true;
    }

    public function stream_lock($operation)
    {
        return $this->fh ? flock($this->fh, $operation) : false;
    }

    public function stream_truncate($size)
    {
        return $this->fh ? ftruncate($this->fh, $size) : false;
    }

    public function stream_stat()
    {
        if ($this->fh) {
            return fstat($this->fh);
        }
        return ['size' => strlen((string)$this->data), 'mode' => 0100444];
    }

    public function stream_set_option($option, $arg1, $arg2)
    {
        return false;
    }

    public function stream_close()
    {
        if ($this->fh) {
            fclose($this->fh);
        }
        $this->fh = null;
        $this->data = null;
    }

    public function stream_metadata($path, $option, $value)
    {
        $real = self::real((string)$path);
        switch ($option) {
            case STREAM_META_TOUCH:
                return @touch($real, $value[0] ?? null, $value[1] ?? null);
            case STREAM_META_ACCESS:
                return @chmod($real, $value);
            case STREAM_META_OWNER:
            case STREAM_META_OWNER_NAME:
                return function_exists('chown') && @chown($real, $value);
            case STREAM_META_GROUP:
            case STREAM_META_GROUP_NAME:
                return function_exists('chgrp') && @chgrp($real, $value);
        }
        return false;
    }

    public function url_stat($path, $flags)
    {
        $real = self::real((string)$path);
        if ($flags & STREAM_URL_STAT_QUIET) {
            return ($flags & STREAM_URL_STAT_LINK) ? @lstat($real) : @stat($real);
        }
        return ($flags & STREAM_URL_STAT_LINK) ? lstat($real) : stat($real);
    }

    public function unlink($path)
    {
        return @unlink(self::real((string)$path));
    }

    public function rename($from, $to)
    {
        return @rename(self::real((string)$from), self::real((string)$to));
    }

    public function mkdir($path, $mode, $options)
    {
        return @mkdir(self::real((string)$path), $mode, (bool)($options & STREAM_MKDIR_RECURSIVE));
    }

    public function rmdir($path, $options)
    {
        return @rmdir(self::real((string)$path));
    }

    public function dir_opendir($path, $options)
    {
        $dh = @opendir(self::real((string)$path));
        if (!$dh) {
            return false;
        }
        $this->dh = $dh;
        return true;
    }

    public function dir_readdir()
    {
        return $this->dh ? readdir($this->dh) : false;
    }

    public function dir_rewinddir()
    {
        if ($this->dh) {
            rewinddir($this->dh);
        }
        return true;
    }

    public function dir_closedir()
    {
        if ($this->dh) {
            closedir($this->dh);
        }
        $this->dh = null;
        return true;
    }
}
