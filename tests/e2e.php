<?php
declare(strict_types=1);

/**
 * End-to-end test:  php tests/e2e.php
 *
 * Encodes a sample app, starts the reference license server and runs the encoded app
 * under several license scenarios, over CLI and over HTTP (activation flow).
 * Every PHP subprocess runs with error_reporting=-1, so deprecations fail the test.
 */

$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pyp-e2e-' . bin2hex(random_bytes(3));
$src = "$tmp/src";
$out = "$tmp/out";
mkdir("$src/lib", 0777, true);
mkdir("$src/tpl");
mkdir("$src/public");
$fails = 0;
$procs = [];

// PYP_EXT_PATH=/path/to/pyp.so loads the native extension into every subprocess
define('STRICT', array_merge(
    ['-d', 'error_reporting=-1', '-d', 'display_errors=stderr', '-d', 'display_startup_errors=1'],
    getenv('PYP_EXT_PATH') ? ['-d', 'extension=' . getenv('PYP_EXT_PATH')] : []
));

function check(string $name, bool $ok, string $detail = ''): void
{
    global $fails;
    echo ($ok ? '  ok   ' : '  FAIL ') . $name . ($ok || $detail === '' ? '' : "\n         " . str_replace("\n", "\n         ", $detail)) . "\n";
    $fails += $ok ? 0 : 1;
}

/** Run a PHP script (strict error reporting); returns [stdout, stderr, exit]. */
function php(array $args, array $env = []): array
{
    $cmd = array_merge([PHP_BINARY], STRICT, $args);
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env + getenv());
    $o = stream_get_contents($pipes[1]);
    $e = stream_get_contents($pipes[2]);
    return [trim((string)$o), trim((string)$e), proc_close($proc)];
}

function pyp(array $args): array
{
    global $root;
    return php(array_merge([$root . '/bin/pyp'], $args));
}

function startServer(string $docroot, array $env): int
{
    global $procs, $tmp;
    $port = random_int(20000, 40000);
    $log = "$tmp/server-$port.log";
    $procs[] = $p = proc_open(
        array_merge(
            [PHP_BINARY, '-d', 'error_reporting=-1', '-d', 'display_errors=1'],
            getenv('PYP_EXT_PATH') ? ['-d', 'extension=' . getenv('PYP_EXT_PATH')] : [],
            ['-S', "127.0.0.1:$port", '-t', $docroot]
        ),
        [0 => ['pipe', 'r'], 1 => ['file', $log, 'w'], 2 => ['file', $log, 'a']],
        $pipes,
        null,
        $env + getenv()
    );
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(100000);
    }
    return $port;
}

function stopServer($proc): void
{
    $pid = proc_get_status($proc)['pid'];
    proc_terminate($proc);
    if (PHP_OS_FAMILY === 'Windows') {
        exec("taskkill /F /T /PID $pid 2>NUL");
    }
    usleep(300000);
}

register_shutdown_function(static function () {
    global $procs;
    foreach ($procs as $p) {
        if (proc_get_status($p)['running']) {
            stopServer($p);
        }
    }
});

/** @return array{code:int, headers:array<string,string>, body:string, cookies:array<string,string>} */
function http(string $method, string $url, array $post = [], array $cookies = [], array $headers = []): array
{
    $ch = curl_init($url);
    $hdr = [];
    $cookieHeader = implode('; ', array_map(static fn($k, $v) => "$k=$v", array_keys($cookies), $cookies));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => array_merge($headers, $cookieHeader !== '' ? ["Cookie: $cookieHeader"] : []),
        CURLOPT_HEADERFUNCTION => static function ($ch, $line) use (&$hdr) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = explode(':', $line, 2);
                $hdr[] = [strtolower(trim($k)), trim($v)];
            }
            return strlen($line);
        },
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $body = (string)curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $h = [];
    $c = [];
    foreach ($hdr as [$k, $v]) {
        $h[$k] = $v;
        if ($k === 'set-cookie' && preg_match('/^([^=]+)=([^;]*)/', $v, $m)) {
            $c[$m[1]] = $m[2];
        }
    }
    return ['code' => $code, 'headers' => $h, 'body' => $body, 'cookies' => $c];
}

// ---------------------------------------------------------------- sample app
file_put_contents("$src/lib/Calc.php", <<<'PHP'
<?php
declare(strict_types=1);

namespace Demo;

#[\Attribute]
final class Meta
{
    public function __construct(public string $path)
    {
    }
}

/** Secret sauce */
final class Calc
{
    // constant expressions: __DIR__ stays a pyp:// path, served by the stream wrapper
    private const TPL = __DIR__ . '/../tpl';

    public function __construct(private int $factor = 2)
    {
    }

    public function run(array $numbers): array
    {
        $secretTotal = 0;
        $doubled = array_map(function ($value) use (&$secretTotal) {
            $secretTotal += $value;
            return $value * $this->factor;
        }, $numbers);
        $scale = fn(int $x) => $x * $this->factor + count($numbers);
        $odd = 1 +/* comment between operators */+ 2;
        return ['doubled' => $doubled, 'total' => $secretTotal, 'scaled' => array_map($scale, $numbers), 'odd' => $odd, 'dir' => basename(__DIR__)];
    }

    private function greet(string $personName): string
    {
        $greeting = <<<TXT
            Hello {$personName}, again $personName
            TXT;
        return $greeting;
    }

    public function hello(string $name): string
    {
        return $this->greet($name) . '|' . static::class;
    }

    #[Meta(__DIR__)]
    public function where(string $dir = __DIR__): string
    {
        static $cached = __DIR__;
        $attr = (new \ReflectionMethod($this, 'where'))->getAttributes(Meta::class)[0]->newInstance();
        return basename($dir) . ',' . basename($cached) . ',' . basename($attr->path) . ',' . (is_file(__FILE__) ? 'file' : 'nofile');
    }

    public static function xml(): string
    {
        return trim((string)file_get_contents(self::TPL . '/hello.xml'));
    }
}
PHP);
file_put_contents("$src/tpl/hello.xml", "<hello>secret template</hello>\n");

$modern = PHP_VERSION_ID >= 80400;
if ($modern) {
    file_put_contents("$src/lib/Modern.php", <<<'PHP'
<?php
declare(strict_types=1);

namespace Demo;

final class Modern
{
    public string $upper {
        get => strtoupper($this->name);
    }

    public function __construct(public private(set) string $name, private(set) int $count = 2)
    {
    }

    public function describe(): string
    {
        $parts = [$this->name, $this->upper, (string)$this->count];
        return implode('/', $parts);
    }
}
PHP);
}

file_put_contents("$src/main.php", <<<'PHP'
<?php
declare(strict_types=1);

require_once __DIR__ . '/lib/Calc.php';

$title = 'topvar';
$calc = new Demo\Calc(3);
echo json_encode($calc->run([1, 2, 3])), "\n";
echo $calc->hello('Ann'), "\n";
echo $calc->where(), "\n";
echo Demo\Calc::xml(), "\n";
if (is_file(__DIR__ . '/lib/Modern.php')) {
    require_once __DIR__ . '/lib/Modern.php';
    echo (new Demo\Modern('neo'))->describe(), "\n";
}
echo $title, ' ', basename(__FILE__), "\n";
PHP);
file_put_contents("$src/public/index.php", "<?php\nrequire __DIR__ . '/../main.php';\n");
file_put_contents("$src/pyp.project.json", '{"must":"never be copied"}');

[$expected, $e, $c] = php(["$src/main.php"]);
check('plain sample runs cleanly', $c === 0 && $e === '', $e);
if (getenv('PYP_EXT_PATH')) {
    [$o, $e, $c] = php(['-r', 'echo extension_loaded("pyp") && function_exists("pyp_macs") ? "native" : "missing";']);
    check('native extension is loaded in subprocesses', $o === 'native', "$o $e");
}

// ---------------------------------------------------------------- init + encode
chdir($tmp);
[$o, $e, $c] = pyp(['init', '--name=Demo Shop']);
check('init', $c === 0, $e);

$dataFile = "$tmp/pyp.server.json";
$licPort = random_int(41000, 50000);
$url = "http://127.0.0.1:$licPort/";
[$o, $e, $c] = pyp(['encode', "--src=$src", "--out=$out", "--server=$url", '--data-ext=xml', '--product=Demo Shop',
    '--message-expired=Trial over - buy at example.com']);
check('encode', $c === 0, "$o\n$e");
check('project secrets are not copied', !is_file("$out/pyp.project.json"));
check('constant-expression note emitted', strpos($e, 'pyp:// path') !== false, $e);

$enc = (string)file_get_contents("$out/lib/Calc.php");
check('source not readable in output', strpos($enc, 'secretTotal') === false && strpos($enc, 'Secret sauce') === false);
check('xml encrypted', strpos((string)file_get_contents("$out/tpl/hello.xml"), 'secret template') === false);
check('activation page + config shipped', is_file("$out/pyp/activate.php") && is_file("$out/pyp/pyp-config.php"));

// ---------------------------------------------------------------- license server
$procs[] = $licServer = proc_open(
    [PHP_BINARY, '-d', 'error_reporting=-1', '-d', 'display_errors=1', '-S', "127.0.0.1:$licPort", '-t', "$root/server"],
    [0 => ['pipe', 'r'], 1 => ['file', "$tmp/license-server.log", 'w'], 2 => ['file', "$tmp/license-server.log", 'a']],
    $pp,
    null,
    ['PYP_SERVER_DATA' => $dataFile, 'PYP_RATE_LIMIT' => '0'] + getenv()
);
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $licPort); $i++) {
    usleep(100000);
}

function lic(array $args): string
{
    global $dataFile;
    [$o] = pyp(array_merge(['license:create', "--data=$dataFile"], $args));
    return $o;
}

$cliCache = "$tmp/cache-cli";
function runApp(string $license, array $env = []): array
{
    global $out, $cliCache;
    return php(["$out/main.php"], $env + ['PYP_LICENSE' => $license, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => $cliCache]);
}

echo "cli scenarios\n";
$good = lic(['--domain=*.example.com', '--ip=10.0.0.0/8', '--expires=30d']);
check('license key format (125 bit)', (bool)preg_match('/^PYP(-[0-9A-Z]{5}){5}$/', $good), $good);
[$o, $e, $c] = runApp($good);
check('valid license runs, output identical, no notices/deprecations', $c === 0 && $o === $expected && $e === '', "exit=$c\n$o\n--expected--\n$expected\n--stderr--\n$e");
check('signed grant cached', count(glob("$cliCache/s-*.json") ?: []) === 1);

// editing the cached grant must not extend it
$cf = (glob("$cliCache/s-*.json") ?: [''])[0];
$cg = json_decode((string)file_get_contents($cf), true);
$cg['resp']['ttl'] = 999999;
$cg['resp']['license']['domains'] = [];
file_put_contents($cf, json_encode($cg));
[$o, $e, $c] = runApp($good);
check('tampered cache is ignored (refetched)', $c === 0 && $o === $expected, $e);

[$o, $e, $c] = runApp(lic(['--domain=other.org']));
check('wrong domain rejected', $c !== 0 && strpos($e, 'not licensed') !== false, "$o $e");
[$o, $e, $c] = runApp(lic(['--ip=192.168.0.0/16']));
check('wrong ip rejected', $c !== 0 && strpos($e, 'not licensed') !== false, "$o $e");
[$o, $e, $c] = runApp(lic(['--mac=de:ad:be:ef:00:01']));
check('wrong mac rejected', $c !== 0 && strpos($e, 'not licensed') !== false, "$o $e");
// shared hosting (e.g. Plesk) restricts file access with open_basedir: /sys and the system
// temp dir are not readable there. The loader must still work (regression: glob() === false).
$basedir = implode(PATH_SEPARATOR, [$tmp, $root]);
[$o, $e, $c] = php(['-d', "open_basedir=$basedir", "$out/main.php"],
    ['PYP_LICENSE' => $good, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => "$tmp/cache-basedir"]);
check('runs under open_basedir like on Plesk (no warnings)', $c === 0 && $o === $expected && $e === '', "$o\n$e");
[$o, $e, $c] = php(['-d', "open_basedir=$basedir", "$out/main.php"],
    ['PYP_LICENSE' => $good, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => '']);
check('runs under open_basedir without a usable cache dir', $c === 0 && $o === $expected && $e === '', "$o\n$e");
[$myMac] = php(['-r', 'require $argv[1]; echo \Pyp\Loader::hostInfo()["macs"][0] ?? "";', "$root/loader/pyp-loader.php"]);
if ($myMac !== '') {
    [$o, $e, $c] = runApp(lic(["--mac=$myMac"]));
    check("license bound to this machine's MAC runs ($myMac)", $c === 0 && $o === $expected, "$o $e");
}
$installPath = str_replace('\\', '/', (string)realpath($out));
[$o, $e, $c] = runApp(lic(["--path=$installPath"]));
check('license bound to the installation path runs', $c === 0 && $o === $expected, "$o $e");
[$o, $e, $c] = runApp(lic(['--path=' . dirname($installPath) . '/*']));
check('path wildcard (parent/*) matches', $c === 0 && $o === $expected, "$o $e");
[$o, $e, $c] = runApp(lic(['--path=/srv/other-shop']));
check('wrong installation path rejected', $c !== 0 && strpos($e, 'not licensed') !== false, "$o $e");

// a refused check from another context (cron job reporting the machine's hostname, a second
// virtual host) must not lock out the licensed site (regression: shared negative cache)
$ctxKey = lic(['--domain=*.example.com', '--ttl=0']);
$ctxEnv = ['PYP_CACHE_DIR' => "$tmp/cache-ctx"];
[$o, $e, $c] = runApp($ctxKey, $ctxEnv);
[$o2, $e2, $c2] = runApp($ctxKey, ['PYP_DOMAIN' => 'web01'] + $ctxEnv);
[$o3, $e3, $c3] = runApp($ctxKey, $ctxEnv);
check('refused check from another host context does not lock out the licensed one',
    $c === 0 && $c2 !== 0 && strpos($e2, 'not licensed') !== false && $c3 === 0 && $o3 === $expected, "$e | $e2 | $e3");

// CLI runs (cron, artisan) have no domain unless PYP_DOMAIN is set: the domain restriction is skipped
[$o, $e, $c] = php(["$out/main.php"], ['PYP_LICENSE' => lic(['--domain=*.example.com']), 'PYP_DOMAIN' => '', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => "$tmp/cache-nodomain"]);
check('CLI without PYP_DOMAIN passes a domain restriction', $c === 0 && $o === $expected, "$o $e");

[$o, $e, $c] = runApp(lic(['--updates-until=2020-01-01']));
check('build newer than the update period is refused', $c !== 0 && strpos($e, 'update period') !== false, "$o $e");
$typed = lic(['--updates-until=365d', '--support-until=2027-03-31', '--type=premium']);
[$o, $e, $c] = runApp($typed);
check('build within the update period runs', $c === 0 && $o === $expected, "$o $e");
[$o, $e, $c] = php(['-r', 'require $argv[1]; echo json_encode(\Pyp\Loader::license());', "$out/pyp/pyp-loader.php"],
    ['PYP_LICENSE' => $typed, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => $cliCache]);
$info = json_decode($o, true);
check('Loader::license() exposes type, support and update dates', ($info['valid'] ?? false) === true && ($info['type'] ?? '') === 'premium'
    && strncmp((string)($info['support_until'] ?? ''), '2027-03-31', 10) === 0 && !empty($info['updates_until']), "$o $e");

[$o, $e, $c] = runApp(lic(['--expires=2020-01-01']));
check('expired license shows custom message', $c !== 0 && strpos($e, 'Trial over - buy at example.com') !== false, "$o $e");
$rev = lic([]);
pyp(['license:revoke', $rev, "--data=$dataFile"]);
[$o, $e, $c] = runApp($rev);
check('revoked license rejected', $c !== 0, "$o $e");
[$o, $e, $c] = runApp('PYP-NOPE0-NOPE0-NOPE0-NOPE0-NOPE0');
check('unknown license rejected', $c !== 0 && strpos($e, 'invalid') !== false, "$o $e");
[$o, $e, $c] = runApp('', ['PYP_LICENSE' => '']);
check('missing license reported', $c !== 0 && strpos($e, 'No license key') !== false, "$o $e");

$f = "$out/lib/Calc.php";
$bytes = (string)file_get_contents($f);
file_put_contents($f, substr_replace($bytes, chr(ord($bytes[strlen($bytes) - 40]) ^ 1), strlen($bytes) - 40, 1));
[$o, $e, $c] = runApp($good);
check('tampered file rejected', $c !== 0 && strpos($e, 'corrupt') !== false, "$o $e");
file_put_contents($f, $bytes);

echo "source extraction attempts\n";
file_put_contents("$out/attacker.php", <<<'PHP'
<?php
require __DIR__ . '/pyp/pyp-loader.php';
\Pyp\Loader::configure(['throw' => true]);
\Pyp\Loader::register();
$f = realpath(__DIR__ . '/lib/Calc.php');
$leak = static fn($s) => is_string($s) && (strpos($s, 'function run') !== false || strpos($s, 'array_map') !== false);
$r = [];
$r[] = 'fopen:' . ($leak(@file_get_contents('pyp://' . $f)) ? 'LEAK' : 'denied');
ob_start(); @highlight_file('pyp://' . $f); $r[] = 'highlight:' . ($leak(ob_get_clean()) ? 'LEAK' : 'denied');
$r[] = 'strip:' . ($leak(@php_strip_whitespace('pyp://' . $f)) ? 'LEAK' : 'denied');
ob_start(); @show_source('pyp://' . $f); $r[] = 'show_source:' . ($leak(ob_get_clean()) ? 'LEAK' : 'denied');
try { $s = @(new SplFileObject('pyp://' . $f))->fread(100000); $r[] = 'spl:' . ($leak($s) ? 'LEAK' : 'denied'); } catch (\Throwable $e) { $r[] = 'spl:denied'; }
try { $u = \Pyp\Loader::open($f); $r[] = 'open:' . ($leak(@file_get_contents($u)) ? 'LEAK' : 'denied'); } catch (\Throwable $e) { $r[] = 'open:denied'; }
try { $r[] = 'read:' . ($leak(\Pyp\Loader::read($f)) ? 'LEAK' : 'denied'); } catch (\Throwable $e) { $r[] = 'read:denied'; }
$r[] = 'data:' . (strpos(\Pyp\Loader::read(__DIR__ . '/tpl/hello.xml'), 'secret template') !== false ? 'readable' : 'broken');
echo implode("\n", $r);
PHP);
[$o, $e, $c] = php(["$out/attacker.php"], ['PYP_LICENSE' => $good, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => $cliCache]);
$want = "fopen:denied\nhighlight:denied\nstrip:denied\nshow_source:denied\nspl:denied\nopen:denied\nread:denied\ndata:readable";
check('decrypted PHP is only handed to include/require', $o === $want, "$o\n$e");
unlink("$out/attacker.php");

echo "web activation flow\n";
$webEnv = ['PYP_CACHE_DIR' => "$tmp/cache-web", 'PYP_LICENSE' => '', 'PYP_DOMAIN' => '', 'PYP_IP' => ''];
$appPort = startServer($out, $webEnv);
$base = "http://127.0.0.1:$appPort";

$r = http('GET', "$base/main.php?x=1");
check('unlicensed page redirects to activation', $r['code'] === 302
    && ($r['headers']['location'] ?? '') === '/pyp/activate.php?reason=missing&return=%2Fmain.php%3Fx%3D1', json_encode($r['headers']) . $r['body']);
$r = http('GET', "$base/main.php", [], [], ['Accept: application/json']);
$j = json_decode($r['body'], true);
check('json clients get 403 + activation_url', $r['code'] === 403 && ($j['error'] ?? '') === 'missing' && strpos((string)($j['activation_url'] ?? ''), '/pyp/activate.php') === 0, $r['body']);

$r = http('GET', "$base/pyp/activate.php?reason=missing&return=%2Fmain.php");
check('activation page renders (no redirect loop)', $r['code'] === 200 && strpos($r['body'], 'name="license"') !== false, (string)$r['code'] . substr($r['body'], 0, 300));
check('activation page sends CSP + frame protection', isset($r['headers']['content-security-policy']) && ($r['headers']['x-frame-options'] ?? '') === 'DENY');
$csrf = $r['cookies']['pyp_csrf'] ?? '';
check('csrf cookie set', strlen($csrf) === 64);

$webKey = lic(['--domain=127.0.0.1', '--ttl=0']);
$r = http('POST', "$base/pyp/activate.php", ['pyp_action' => 'activate', 'license' => $webKey, 'csrf' => 'forged', 'return' => '/main.php'], ['pyp_csrf' => $csrf]);
check('activation without valid csrf token refused', $r['code'] === 200 && strpos($r['body'], 'session has expired') !== false && !is_file("$out/pyp/license.php"));
$r = http('POST', "$base/pyp/activate.php", ['pyp_action' => 'activate', 'license' => 'PYP-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE', 'csrf' => $csrf, 'return' => '/main.php'], ['pyp_csrf' => $csrf]);
check('unknown key refused on activation page', strpos($r['body'], 'invalid') !== false && !is_file("$out/pyp/license.php"), substr($r['body'], -400));
$r = http('POST', "$base/pyp/activate.php", ['pyp_action' => 'activate', 'license' => strtolower($webKey), 'csrf' => $csrf, 'return' => '//evil.example/x'], ['pyp_csrf' => $csrf]);
check('valid key activates, open redirect blocked', $r['code'] === 303 && ($r['headers']['location'] ?? '') === '/pyp/activate.php' && is_file("$out/pyp/license.php"), $r['code'] . json_encode($r['headers']) . substr($r['body'], -300));

$r = http('GET', "$base/main.php");
check('licensed page runs over HTTP, identical output', $r['code'] === 200 && trim($r['body']) === $expected, $r['code'] . "\n" . $r['body']);
$r = http('GET', "$base/pyp/license.php");
check('stored license is not served', strpos($r['body'], $webKey) === false && $r['code'] === 404, $r['code'] . $r['body']);
$r = http('GET', "$base/pyp/activate.php");
check('active license is shown, form hidden', strpos($r['body'], 'is active') !== false && strpos($r['body'], 'name="license"') === false, substr($r['body'], -400));
$other = lic(['--domain=127.0.0.1']);
$r = http('POST', "$base/pyp/activate.php", ['pyp_action' => 'activate', 'license' => $other, 'csrf' => $csrf], ['pyp_csrf' => $csrf]);
check('active license cannot be replaced by visitors', strpos((string)file_get_contents("$out/pyp/license.php"), $webKey) !== false, substr($r['body'], -300));

// docroot without the loader directory -> activation page is rendered in place
$pubPort = startServer("$out/public", $webEnv);
$r = http('GET', "http://127.0.0.1:$pubPort/index.php");
check('front controller works with the stored license', $r['code'] === 200 && trim($r['body']) === $expected, $r['code'] . $r['body']);

pyp(['license:revoke', $webKey, "--data=$dataFile"]);
$r = http('GET', "$base/main.php");
check('revoked license sends visitors back to activation', $r['code'] === 302 && strpos($r['headers']['location'] ?? '', 'reason=unauthorized') !== false, json_encode($r['headers']));
$r = http('GET', "http://127.0.0.1:$pubPort/index.php");
check('inline activation form when activate.php has no URL', $r['code'] === 403 && strpos($r['body'], 'name="license"') !== false
    && strpos($r['body'], 'action="/index.php"') !== false, $r['code'] . substr($r['body'], 0, 300));
$csrf2 = $r['cookies']['pyp_csrf'] ?? $csrf;
$r = http('POST', "http://127.0.0.1:$pubPort/index.php", ['pyp_action' => 'activate', 'license' => $other, 'csrf' => $csrf2], ['pyp_csrf' => $csrf2]);
check('inline activation stores the new key and returns to the page', $r['code'] === 303 && ($r['headers']['location'] ?? '') === '/index.php'
    && strpos((string)file_get_contents("$out/pyp/license.php"), $other) !== false, $r['code'] . json_encode($r['headers']) . substr($r['body'], -300));
$r = http('GET', "http://127.0.0.1:$pubPort/index.php");
check('page works again after inline activation', $r['code'] === 200 && trim($r['body']) === $expected, $r['code'] . $r['body']);

$logs = '';
foreach (glob("$tmp/*.log") ?: [] as $l) {
    $logs .= (string)file_get_contents($l);
}
check('no warnings/deprecations in server logs', !preg_match('/(Deprecated|Warning|Notice|Fatal error)/', $logs), implode("\n", preg_grep('/(Deprecated|Warning|Notice|Fatal)/', explode("\n", $logs))));

$legacy = getenv('PYP_LEGACY_PHP');
if ($legacy) {
    echo "loader on legacy PHP ($legacy)\n";
    mkdir("$tmp/legacy-src");
    file_put_contents("$tmp/legacy-src/app.php", "<?php\nfunction pyp_legacy(array \$items) { \$sum = 0; foreach (\$items as \$i) { \$sum += \$i; } return \$sum . '|' . basename(__DIR__); }\necho pyp_legacy([1, 2, 3]), \"\\n\";\n");
    [$o, $e, $c] = pyp(['encode', "--src=$tmp/legacy-src", "--out=$tmp/legacy-out", "--server=$url"]);
    $cmd = array_merge([$legacy], STRICT, ["$tmp/legacy-out/app.php"]);
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $lp, null,
        ['PYP_LICENSE' => $good, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => "$tmp/cache-legacy"] + getenv());
    $lo = trim((string)stream_get_contents($lp[1]));
    $le = trim((string)stream_get_contents($lp[2]));
    proc_close($proc);
    check('encoded file runs on legacy PHP via license server', $lo === '6|legacy-out' && $le === '', "$lo\n$le");
}

echo "native extension (--require-ext)\n";
$outExt = "$tmp/out-ext";
[$o, $e, $c] = pyp(['encode', "--src=$src", "--out=$outExt", "--server=$url", '--data-ext=xml', '--require-ext']);
check('encode --require-ext', $c === 0 && strpos($e, 'pyp:// path') === false, "$o\n$e");
check('source not readable in --require-ext output', strpos((string)file_get_contents("$outExt/lib/Calc.php"), 'secretTotal') === false);
$extEnv = ['PYP_LICENSE' => $good, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => $cliCache];
[$hook] = php(['-r', 'echo function_exists("pyp_ext_info") && !empty(pyp_ext_info()["features"]["compile_hook"]) ? "yes" : "no";']);
// the PHP loader must never hand out the source of such a file, with or without the extension
file_put_contents("$outExt/attacker.php", <<<'PHP'
<?php
require __DIR__ . '/pyp/pyp-loader.php';
\Pyp\Loader::configure(['throw' => true]);
\Pyp\Loader::register();
$f = realpath(__DIR__ . '/lib/Calc.php');
try { include 'pyp://' . $f; echo "include:LEAK\n"; } catch (\Pyp\LicenseException $e) { echo 'include:', $e->type, "\n"; }
try { \Pyp\Loader::read($f); echo "read:LEAK\n"; } catch (\Pyp\LicenseException $e) { echo 'read:', $e->type, "\n"; }
PHP);
[$o, $e, $c] = php(["$outExt/attacker.php"], $extEnv);
check('PHP loader refuses --require-ext files', $o === "include:extension\nread:denied", "$o\n$e");
unlink("$outExt/attacker.php");
if ($hook === 'yes') {
    [$o, $e, $c] = php(["$outExt/main.php"], $extEnv);
    check('compile hook runs the app, output identical, no notices', $c === 0 && $o === $expected && $e === '', "exit=$c\n$o\n--stderr--\n$e");
    [$o, $e, $c] = php(['-d', 'opcache.enable=1', '-d', 'opcache.enable_cli=1', "$outExt/main.php"], $extEnv);
    check('compile hook works with OPcache enabled', $c === 0 && $o === $expected && $e === '', "exit=$c\n$o\n--stderr--\n$e");
    file_put_contents("$outExt/paths.php", "<?php\nnamespace Demo;\nconst HERE = __DIR__;\nrequire_once __DIR__ . '/lib/Calc.php';\nrequire_once __DIR__ . '/lib/Calc.php';\n"
        . "echo basename(__FILE__), '|', (int)(HERE === __DIR__ && is_dir(HERE)), '|', count(array_filter(get_included_files(), static fn(\$f) => basename(\$f) === 'Calc.php')), \"\\n\";\n");
    mkdir("$tmp/ext-one");
    copy("$outExt/paths.php", "$tmp/ext-one/paths.php");
    pyp(['encode', "--src=$tmp/ext-one", "--out=$outExt", "--server=$url", '--require-ext']);
    [$o, $e, $c] = php(["$outExt/paths.php"], $extEnv);
    check('real __FILE__/__DIR__ (also in constant expressions), include_once tracking', $c === 0 && $o === 'paths.php|1|1' && $e === '', "exit=$c\n$o\n$e");
    [$o, $e, $c] = php(["$outExt/main.php"], ['PYP_LICENSE' => ''] + $extEnv);
    check('compile hook: missing license reported', $c !== 0 && strpos($e, 'No license key') !== false && strpos($o . $e, 'secretTotal') === false, "exit=$c\n$o\n$e");
    [$o, $e, $c] = php(["$outExt/main.php"], ['PYP_LICENSE' => $rev] + $extEnv);
    check('compile hook: revoked license rejected', $c !== 0, "exit=$c\n$o\n$e");
    $f = "$outExt/lib/Calc.php";
    $bytes = (string)file_get_contents($f);
    file_put_contents($f, substr_replace($bytes, chr(ord($bytes[strlen($bytes) - 40]) ^ 1), strlen($bytes) - 40, 1));
    [$o, $e, $c] = php(["$outExt/main.php"], $extEnv);
    check('compile hook: tampered file rejected', $c !== 0 && strpos($e, 'corrupt') !== false, "exit=$c\n$o\n$e");
    file_put_contents($f, $bytes);
    [$o, $e, $c] = php(["$out/main.php"], $extEnv);
    check('files built without --require-ext still run with the hook installed', $c === 0 && $o === $expected && $e === '', "exit=$c\n$o\n$e");
} else {
    [$o, $e, $c] = php(["$outExt/main.php"], $extEnv);
    check('without the extension the file refuses to run', $c !== 0 && $o === '' && strpos($e, 'requires the PYP PHP extension') !== false, "exit=$c\n$o\n$e");
}

echo "license server down\n";
$fresh = lic(['--domain=*.example.com']);
// build with a grace period + a grant that is already past its ttl
mkdir("$tmp/grace-src");
file_put_contents("$tmp/grace-src/app.php", "<?php echo 'grace-ok';\n");
pyp(['encode', "--src=$tmp/grace-src", "--out=$tmp/grace-out", "--server=$url", '--grace=3600']);
$graceKey = lic(['--ttl=0']);
$graceEnv = ['PYP_LICENSE' => $graceKey, 'PYP_DOMAIN' => 'shop.example.com', 'PYP_IP' => '10.1.2.3', 'PYP_CACHE_DIR' => "$tmp/cache-grace"];
[$o, $e, $c] = php(["$tmp/grace-out/app.php"], $graceEnv);
check('build with grace period runs', $c === 0 && $o === 'grace-ok', "$o $e");
stopServer($licServer);
[$o, $e, $c] = runApp($fresh);
check('unreachable server reported', $c !== 0 && strpos($e, 'could not be reached') !== false, "$o $e");
[$o, $e, $c] = runApp($good);
check('cached grant keeps working while the server is down', $c === 0 && $o === $expected, $e);
[$o, $e, $c] = php(["$tmp/grace-out/app.php"], $graceEnv);
check('expired grant is used within the grace period', $c === 0 && $o === 'grace-ok', "$o $e");

// Something else answers on the license URL: rate limit, proxy/WAF error page, wrong vhost.
// Unsigned answers say nothing about the license - they must not delete a valid grant.
mkdir("$tmp/stub");
file_put_contents("$tmp/stub/index.php", '<?php http_response_code(429); header("Content-Type: application/json"); echo \'{"status":"invalid","message":"Too many requests."}\';');
$procs[] = $stub = proc_open([PHP_BINARY, '-S', "127.0.0.1:$licPort", '-t', "$tmp/stub"],
    [0 => ['pipe', 'r'], 1 => ['file', "$tmp/stub.txt", 'w'], 2 => ['file', "$tmp/stub.txt", 'a']], $sp);
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $licPort); $i++) {
    usleep(100000);
}
array_map('unlink', glob("$tmp/cache-grace/n-*.json") ?: []);   // forget the "unreachable" result from above (remembered for 30 s)
[$o, $e, $c] = php(["$tmp/grace-out/app.php"], $graceEnv);
check('unsigned answer (HTTP 429) keeps the grant usable within the grace period',
    $c === 0 && $o === 'grace-ok' && count(glob("$tmp/cache-grace/s-*.json") ?: []) === 1, "$o $e");
[$o, $e, $c] = runApp(lic(['--domain=*.example.com']));
check('unsigned answer is reported as unreachable, not as an invalid license', $c !== 0 && strpos($e, 'could not be reached') !== false, "$o $e");
stopServer($stub);

echo "external key\n";
$out2 = "$tmp/out2";
[$o, $e, $c] = pyp(['encode', "--src=$src", "--out=$out2", "--external-key=file:$tmp/ext.key", '--external-key-value=hunter2', '--data-ext=xml']);
check('encode with external key', $c === 0, "$o $e");
[$o, $e, $c] = php(["$out2/main.php"]);
check('missing external key rejected', $c !== 0 && strpos($e, 'key is missing') !== false, "$o $e");
file_put_contents("$tmp/ext.key", "hunter2\n");
[$o, $e, $c] = php(["$out2/main.php"]);
check('external key unlocks, output identical', $c === 0 && $o === $expected && $e === '', "$o $e");
file_put_contents("$tmp/ext.key", 'wrong');
[$o, $e, $c] = php(["$out2/main.php"]);
check('wrong external key rejected', $c !== 0, "$o $e");

echo "\nPHP " . PHP_VERSION . ($modern ? ' (incl. PHP 8.4 syntax)' : '') . ': ' . ($fails === 0 ? "ALL PASSED\n" : "$fails FAILED\n");
exit($fails === 0 ? 0 : 1);
