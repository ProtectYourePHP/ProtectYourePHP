# Native extension (`ext/`) and publishing

ProtectYourePHP ships in two parts:

| Part | Where | Published as | Install |
|---|---|---|---|
| Encoder, CLI, loader, reference license server | repository root | Composer package `protectyourephp/protectyourephp` (Packagist) | `composer require --dev protectyourephp/protectyourephp` |
| Native extension `pyp` | `ext/` | PIE package `protectyourephp/pyp-ext` | `pie install protectyourephp/pyp-ext` |

The loader works without the extension. When the extension is installed it is
detected automatically (`function_exists('pyp_macs')`).

## What the extension does today (0.2.0)

* **Compile hook** for files built with `pyp encode --require-ext`: the extension recognises
  the PYP container when PHP compiles the file, obtains the file key from `pyp-loader.php`
  (which still does the licensing), decrypts and passes the source straight to the compiler
  under the file's real path. The decrypted source never becomes a PHP value, there is no
  `Loader::open()` to patch, and `__FILE__` / `__DIR__` are the real paths. Without the
  extension such files refuse to run, and the PHP loader refuses to decrypt them.
  Current limits: the file key still passes through PHP code, decryption calls ext-sodium,
  and protected files are compiled on every request (not stored in OPcache) so the license
  is checked each time. Data files (`--data-ext`) are still decrypted by the PHP loader: read them with
  `\Pyp\Loader::read($file)`. A plain `file_get_contents(__DIR__ . '/x.xml')` returns the
  encrypted bytes, because `__DIR__` is the real path here and not a `pyp://` path.
* `pyp_macs(): array` - MAC addresses via `getifaddrs()` (Linux/BSD/macOS) or
  `GetAdaptersAddresses()` (Windows). Works on hosts where `exec()` is disabled and
  `net_get_interfaces()` reports no MAC addresses (Linux).
* `pyp_ext_info(): array` - version, `loader_api` and a feature list, so newer loaders
  can feature-detect older extensions.
* Constants `PYP_EXT_VERSION`, `PYP_LOADER_API`, a `phpinfo()` section.

Supported: PHP 8.1 - 8.5, NTS and ZTS, Linux/macOS (`config.m4`) and Windows (`config.w32`).

## Building locally

```bash
cd ext
phpize
./configure --enable-pyp
make
make test TESTS=tests NO_INTERACTION=1
php -d extension=$PWD/modules/pyp.so -r 'var_dump(pyp_ext_info());'
```

Windows: build inside the PHP SDK (`phpsdk-vs17-x64.bat`), place `ext/` as
`php-src/ext/pyp`, then `buildconf && configure --enable-pyp=shared && nmake`.

CI (`.github/workflows/ci.yml`) builds and tests the extension for PHP 8.1 - 8.5 (NTS, plus
ZTS on 8.4) and runs the complete end-to-end suite with the extension loaded.

## Publishing

### 1. Library -> Packagist

1. Push the repository to GitHub, tag a release (`git tag v1.1.0 && git push --tags`).
2. Submit the repository URL on <https://packagist.org/packages/submit>.
3. Enable the GitHub hook so new tags are picked up automatically.

`composer.json` excludes `tests/`, `ext/` and `.github/` from dist archives.

### 2. Extension -> PIE

[PIE](https://github.com/php/pie) (the PHP Foundation's successor to PECL) installs
extensions from Packagist packages of `"type": "php-ext"`. That `composer.json` has to be
at the root of its own repository, so the extension is published from a split repository:

The split repository is [`ProtectYourePHP/pyp-ext`](https://github.com/ProtectYourePHP/pyp-ext).
`ext/` contains everything it needs (README, LICENSE, `.github/workflows`).

```bash
# sync ext/ to the extension repository (run from the main repository)
git subtree split --prefix=ext -b ext-release
git push https://github.com/ProtectYourePHP/pyp-ext.git ext-release:main
# release
gh release create 0.1.0 --repo ProtectYourePHP/pyp-ext --target main --title "pyp 0.1.0" --notes "..."
```

Then submit `https://github.com/ProtectYourePHP/pyp-ext` on Packagist (package name
`protectyourephp/pyp-ext`; the repositories have to be public for that). Users install it with
`pie install protectyourephp/pyp-ext` - PIE runs `phpize`, `configure`, `make`,
`make install` and enables the extension in `php.ini`.

**Windows:** PIE downloads prebuilt DLLs from the GitHub release. `ext/.github/workflows/windows.yml`
uses the official [php-windows-builder](https://github.com/php/php-windows-builder) actions to build
them for every PHP version / TS mode and attaches them when a release is published.

## Roadmap: native loader (`loader_api` 2)

The pure PHP loader cannot hide decrypted source from someone who controls the server: it is
plain PHP and can be patched. The extension is where this changes:

1. **`zend_compile_file` hook.** The extension recognises PYP containers (trailer +
   `PYP1` magic) when PHP compiles a file, decrypts in C and passes the source to the
   original compiler. Decrypted source never exists as a PHP string, the `pyp://` wrapper and
   the PHP stub are no longer needed, and OPcache caches the compiled opcodes.
2. **Key handling in C.** License request, signature check and key derivation move into
   the extension (libsodium is already linked into PHP), so the key share never enters
   userland memory. The JSON protocol (`docs/license-protocol.md`) stays the same.
3. **Hardening.** Refuse to run when the engine is being traced (`zend_extension`
   debuggers, `opcache.file_cache` inspection), zero buffers after compilation.
4. **Format v2.** Containers that require `loader_api >= 2` can omit the embedded key
   part, so they only run where the native extension is installed.

Step 1 is implemented in 0.2.0 (`pyp_ext_info()['features']['compile_hook']` is `true`,
`PYP_LOADER_API` is 2), without the OPcache part. Step 2 removes the remaining PHP
round trip for the key.
