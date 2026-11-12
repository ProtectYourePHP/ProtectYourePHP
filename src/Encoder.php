<?php
declare(strict_types=1);

namespace Pyp;

require_once __DIR__ . '/../loader/pyp-loader.php';
require_once __DIR__ . '/Obfuscator.php';

/**
 * Encrypts PHP files (and arbitrary data files) into the PYP container format.
 *
 * Options:
 *   project        array   contents of pyp.project.json (project, secret, sign_public, ...)
 *   product        ?string product name shown on the activation page
 *   server_url     ?string license server URL -> enables the dynamic (server issued) key layer
 *   license        ?string bake a license key into the files (per-customer builds)
 *   external       ?array  ['type'=>'file'|'env', 'ref'=>path|name, 'secret'=>string]
 *   obfuscate      bool    rename local variables (default true)
 *   strip_comments bool    default true
 *   keep_docblocks bool    default false
 *   php_ext        string[] extensions encoded as executable PHP
 *   data_ext       string[] extensions encrypted as data (xml, tpl, ...)
 *   exclude        string[] fnmatch patterns (relative paths) that are skipped entirely
 *   messages       array   missing|expired|unauthorized|unreachable|invalid|key|corrupt => text
 *   grace          int     seconds a cached key may be used when the server is unreachable (default 72 h)
 *   loader_dir     string  directory (relative to the output root) the loader is copied to
 *   activation_url ?string URL of activate.php (default: derived from DOCUMENT_ROOT at runtime)
 *   allow_change   bool    allow replacing an active license on the activation page
 */
final class Encoder
{
    /** Files that must never end up in a distribution. */
    private const SECRET_FILES = ['pyp.project.json', 'pyp.server.json'];

    private array $o;
    /** @var string[] */
    public array $warnings = [];

    public function __construct(array $options)
    {
        $this->o = $options + [
            'product' => null, 'server_url' => null, 'license' => null, 'external' => null,
            'obfuscate' => true, 'strip_comments' => true, 'keep_docblocks' => false,
            'php_ext' => ['php', 'phtml', 'inc'], 'data_ext' => [], 'exclude' => [],
            'messages' => [], 'grace' => 259200, 'loader_dir' => 'pyp',
            'activation_url' => null, 'allow_change' => false,
        ];
        $p = $this->o['project'] ?? null;
        $secret = is_array($p) ? base64_decode((string)($p['secret'] ?? ''), true) : false;
        $pk = is_array($p) ? base64_decode((string)($p['sign_public'] ?? ''), true) : false;
        if (!is_array($p) || !is_string($p['project'] ?? null) || !preg_match('/^[A-Za-z0-9_-]{4,64}$/', $p['project'])
            || $secret === false || strlen($secret) !== 32 || $pk === false || strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new \InvalidArgumentException('A valid project (see "pyp init") is required.');
        }
        if ($this->o['server_url'] !== null) {
            $url = (string)$this->o['server_url'];
            $parts = parse_url($url);
            $scheme = strtolower((string)($parts['scheme'] ?? ''));
            if (!in_array($scheme, ['http', 'https'], true) || empty($parts['host'])) {
                throw new \InvalidArgumentException('The license server URL must be an http(s) URL.');
            }
            if ($scheme === 'http' && !in_array($parts['host'], ['localhost', '127.0.0.1', '::1', '[::1]'], true)) {
                $this->warnings[] = "license server URL uses plain http ($url) - use https in production";
            }
        }
        if (!preg_match('#^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$#', (string)$this->o['loader_dir']) || strpos((string)$this->o['loader_dir'], '..') !== false) {
            throw new \InvalidArgumentException('loader_dir must be a relative path without "..".');
        }
        if ($this->o['license'] !== null && !preg_match(Loader::KEY_PATTERN, Loader::normalizeKey((string)$this->o['license']))) {
            throw new \InvalidArgumentException('Invalid license key format.');
        }
        if ($this->o['external'] !== null && trim((string)($this->o['external']['secret'] ?? '')) === '') {
            throw new \InvalidArgumentException('The external key value must not be empty.');
        }
    }

    /** @return array{php:int,data:int,copied:int,skipped:int} */
    public function encodeDirectory(string $src, string $out): array
    {
        $srcReal = realpath($src);
        if ($srcReal === false || !is_dir($srcReal)) {
            throw new \InvalidArgumentException("Source directory not found: $src");
        }
        if (!is_dir($out) && !@mkdir($out, 0777, true)) {
            throw new \RuntimeException("Cannot create output directory: $out");
        }
        $src = rtrim($srcReal, '\\/');
        $out = rtrim((string)realpath($out), '\\/');
        if ($out === $src || strncmp($src . DIRECTORY_SEPARATOR, $out . DIRECTORY_SEPARATOR, strlen($out) + 1) === 0) {
            throw new \InvalidArgumentException('The output directory must not be the source directory or one of its parents.');
        }

        $stats = ['php' => 0, 'data' => 0, 'copied' => 0, 'skipped' => 0];
        $loaderDir = $out . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $this->o['loader_dir']);
        $loaderTarget = $loaderDir . DIRECTORY_SEPARATOR . 'pyp-loader.php';

        $it = new \RecursiveIteratorIterator(new \RecursiveCallbackFilterIterator(
            new \RecursiveDirectoryIterator($src, \FilesystemIterator::SKIP_DOTS),
            static function (\SplFileInfo $f) use ($out): bool {
                return !in_array($f->getFilename(), ['.git', '.svn', '.hg'], true) && $f->getRealPath() !== $out;
            }
        ));
        foreach ($it as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }
            $rel = ltrim(str_replace('\\', '/', substr($file->getPathname(), strlen($src))), '/');
            if (in_array(strtolower($file->getFilename()), self::SECRET_FILES, true)) {
                $this->warnings[] = "$rel: skipped (contains secrets)";
                $stats['skipped']++;
                continue;
            }
            foreach ((array)$this->o['exclude'] as $pattern) {
                if (fnmatch((string)$pattern, $rel)) {
                    $stats['skipped']++;
                    continue 2;
                }
            }
            $dst = $out . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            if (!is_dir(dirname($dst))) {
                mkdir(dirname($dst), 0777, true);
            }
            $kind = $this->kindOf($rel);
            if ($kind === null) {
                copy($file->getPathname(), $dst);
                $stats['copied']++;
                continue;
            }
            $loaderRel = $this->relativePath(dirname($dst), $loaderTarget);
            $this->writeFile($dst, $this->encodeString((string)file_get_contents($file->getPathname()), $kind, $loaderRel, $rel));
            $stats[$kind]++;
        }
        $this->writeLoaderDir($loaderDir);
        return $stats;
    }

    private function writeLoaderDir(string $dir): void
    {
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        copy(__DIR__ . '/../loader/pyp-loader.php', $dir . '/pyp-loader.php');
        $project = $this->o['project'];
        $site = [
            'project' => $project['project'],
            'product' => $this->o['product'] ?? ($project['name'] ?? null),
            'server' => $this->o['server_url'] ? ['url' => $this->o['server_url'], 'pk' => $project['sign_public']] : null,
            'activation_url' => $this->o['activation_url'],
            'allow_change' => (bool)$this->o['allow_change'],
            'messages' => $this->o['messages'],
        ];
        $this->writeFile($dir . '/pyp-config.php', "<?php\n// Generated by ProtectYourePHP. Public settings only, no secrets.\nreturn "
            . var_export($site, true) . ";\n");
        $this->writeFile($dir . '/activate.php', "<?php\n// License activation page (ProtectYourePHP). Unlicensed visitors are redirected here.\n"
            . "require __DIR__ . '/pyp-loader.php';\n\\Pyp\\Activation::run();\n");
        $this->writeFile($dir . '/.htaccess', "# Only the activation page is meant to be requested directly.\n"
            . "<IfModule mod_authz_core.c>\n  Require all denied\n  <Files \"activate.php\">\n    Require all granted\n  </Files>\n</IfModule>\n");
        $this->writeFile($dir . '/index.html', '');
    }

    private function kindOf(string $rel): ?string
    {
        $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
        if (in_array($ext, $this->o['php_ext'], true)) {
            return 'php';
        }
        if (in_array($ext, $this->o['data_ext'], true)) {
            return 'data';
        }
        return null;
    }

    /** Returns the complete content of the encoded file. */
    public function encodeString(string $plain, string $kind, string $loaderRel, string $label = ''): string
    {
        $shebang = '';
        if ($kind === 'php') {
            if (strncmp($plain, '#!', 2) === 0) {
                $nl = strpos($plain, "\n");
                $shebang = $nl === false ? $plain : substr($plain, 0, $nl + 1);
                $plain = $nl === false ? '' : substr($plain, $nl + 1);
            }
            $ob = new Obfuscator();
            try {
                $plain = $ob->transform($plain, [
                    'rename_vars' => (bool)$this->o['obfuscate'],
                    'strip_comments' => (bool)$this->o['strip_comments'],
                    'keep_docblocks' => (bool)$this->o['keep_docblocks'],
                ]);
            } catch (\ParseError $e) {
                throw new \RuntimeException("Syntax error in $label: " . $e->getMessage(), 0, $e);
            }
            foreach ($ob->warnings as $w) {
                $this->warnings[] = "$label: $w";
            }
        }

        $project = $this->o['project'];
        $fileId = bin2hex(random_bytes(8));
        $salt = random_bytes(32);
        $nonce = random_bytes(24);
        $embedded = random_bytes(32);

        $ext = null;
        $layers = ['embedded' => base64_encode($embedded), 'external' => null, 'server' => null];
        if ($this->o['external']) {
            $e = $this->o['external'];
            $ext = Loader::externalBytes((string)$e['secret']);
            $layers['external'] = ['type' => $e['type'], 'ref' => $e['ref']];
        }
        $share = null;
        if ($this->o['server_url']) {
            $share = Loader::projectShare((string)base64_decode($project['secret'], true));
            $layers['server'] = [
                'url' => $this->o['server_url'],
                'pk' => $project['sign_public'],
                'license' => $this->o['license'] !== null ? Loader::normalizeKey((string)$this->o['license']) : null,
            ];
        }

        $header = [
            'v' => 1,
            'project' => $project['project'],
            'file' => $fileId,
            'kind' => $kind,
            'salt' => base64_encode($salt),
            'nonce' => base64_encode($nonce),
            'layers' => $layers,
            'messages' => (object)$this->o['messages'],
            'grace' => max(0, (int)$this->o['grace']),
            'built' => time(),   // checked against the license's "updates_until"
        ];
        $raw = json_encode($header, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $key = Loader::deriveKey($embedded, $ext, $share, $fileId, $salt);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $raw, $nonce, $key);
        sodium_memzero($key);
        $container = Loader::pack($raw, $cipher);

        if ($kind === 'data') {
            return $container;
        }
        $lit = var_export('/' . $loaderRel, true);
        $stub = $shebang
            . "<?php if(!class_exists('Pyp\\\\Loader',false)){if(!is_file(__DIR__.$lit)){http_response_code(500);exit('ProtectYourePHP loader not found.');}"
            . "require_once __DIR__.$lit;}return include \\Pyp\\Loader::open(__FILE__);\n__halt_compiler();";
        return $stub . $container;
    }

    private function writeFile(string $path, string $content): void
    {
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (file_put_contents($tmp, $content) === false || !rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException("Cannot write $path");
        }
    }

    private function relativePath(string $fromDir, string $toFile): string
    {
        $from = explode('/', trim(str_replace('\\', '/', $fromDir), '/'));
        $to = explode('/', trim(str_replace('\\', '/', $toFile), '/'));
        while ($from && $to && $from[0] === $to[0]) {
            array_shift($from);
            array_shift($to);
        }
        return str_repeat('../', count($from)) . implode('/', $to);
    }
}
