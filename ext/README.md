# PYP extension (`pyp`)

Native PHP extension for **PYP (ProtectYourePHP)**, the open source PHP encoder and
licensing system. Files built with `pyp encode --require-ext` only run with this extension.
All other encoded files work without it; when installed, the loader detects it and uses its
native helpers automatically - no code changes needed.

> This repository is split from [`ProtectYourePHP/ProtectYourePHP`](https://github.com/ProtectYourePHP/ProtectYourePHP)
> (`ext/`). Please open pull requests there.

## What it does (0.2)

| | |
|---|---|
| Compile hook | runs files built with `pyp encode --require-ext`: the decrypted source goes straight to the PHP compiler and never reaches PHP code |
| `pyp_macs(): array` | MAC addresses of all non-loopback interfaces (`aa:bb:cc:dd:ee:ff`) - natively, without `exec()` |
| `pyp_ext_info(): array` | `version`, `loader_api`, `features` |
| `PYP_EXT_VERSION`, `PYP_LOADER_API` | constants |

The loader uses `pyp_macs()` for **MAC address binding** of licenses. Without the extension it
falls back to `net_get_interfaces()`, `/sys/class/net` or `exec('ip link')` - which fails on many
shared hosts.

**Compile hook (new in 0.2).** Licensing still happens in `pyp-loader.php`, which hands the
file key to the extension. Protected files are compiled on every request (they are not stored
in OPcache yet). Encrypted data files are read with `\Pyp\Loader::read($file)`.

Supported: PHP 8.1 - 8.5, NTS and ZTS, Linux x86_64, macOS, Windows x64.

## Install

### 1. Find out which build you need

```bash
php -v                                   # PHP version, e.g. 8.4.x
php -i | grep -E "Thread Safety|Compiler|Architecture|PHP Extension Build"
php -i | grep extension_dir              # where extensions go
```

* **Thread Safety** `disabled` = `nts`, `enabled` = `ts`
* Windows: **Compiler** Visual C++ 2019 = `vs16` (PHP 8.1-8.3), Visual C++ 2022 = `vs17` (PHP 8.4+)

### 2a. Windows

1. Download the zip matching your PHP from the [latest release](https://github.com/ProtectYourePHP/pyp-ext/releases/latest),
   e.g. `php_pyp-0.2.0-8.4-nts-vs17-x86_64.zip`.
2. Copy the DLL from the zip into your `extension_dir` (usually `C:\php\ext`) and **rename it to
   `php_pyp.dll`** (in the zip it is called `php_pyp-0.2.0-8.4-nts-vs17-x86_64.dll`; PIE renames it automatically).

   ```powershell
   Expand-Archive php_pyp-0.2.0-8.4-nts-vs17-x86_64.zip -DestinationPath pyp
   Copy-Item pyp\php_pyp-0.2.0-8.4-nts-vs17-x86_64.dll C:\php\ext\php_pyp.dll
   ```

3. Add to `php.ini`:

   ```ini
   extension=pyp
   ```

4. Restart the web server / PHP-FPM / IIS application pool.

### 2b. Linux

**With PIE** (builds for your exact PHP, recommended):

```bash
pie install protectyourephp/pyp-ext
```

**Prebuilt** (`x86_64`, glibc, for PHP from the usual distro/ondrej/sury packages):

```bash
tar -xzf php_pyp-0.2.0-8.4-nts-linux-x86_64.tar.gz
sudo cp php_pyp-0.2.0-8.4-nts-linux-x86_64/pyp.so "$(php-config --extension-dir)/"
echo "extension=pyp" | sudo tee /etc/php/8.4/mods-available/pyp.ini
sudo phpenmod pyp && sudo systemctl reload php8.4-fpm   # Debian/Ubuntu
```

On other distributions add `extension=pyp` to `php.ini` (or a file in `php --ini`'s scan directory).

**From source** (Linux, macOS):

```bash
git clone https://github.com/ProtectYourePHP/pyp-ext.git && cd pyp-ext
phpize
./configure --enable-pyp
make
make test TESTS=tests NO_INTERACTION=1
sudo make install          # then add extension=pyp to php.ini
```

### 3. Check it works

```bash
php -m | grep pyp
php -r 'print_r(pyp_ext_info()); print_r(pyp_macs());'
```

For the web server SAPI, check `phpinfo()`: there is a section **PYP (ProtectYourePHP) support**.

Try it without touching `php.ini`:

```bash
php -d extension=/full/path/to/php_pyp.dll -r 'var_dump(extension_loaded("pyp"));'
```

## Using it with encoded applications

Nothing to configure. When the extension is loaded, the PYP loader (`pyp/pyp-loader.php`)
uses it automatically. Licenses with MAC addresses then work on servers where `exec()` is disabled.

## Roadmap

`loader_api` 2 adds a `zend_compile_file` hook that decrypts PYP files in C, so decrypted
source never reaches userland and OPcache can cache protected code. See
[docs/native-extension.md](https://github.com/ProtectYourePHP/ProtectYourePHP/blob/main/docs/native-extension.md).

## Troubleshooting

| Message | Cause |
|---|---|
| `Unable to load dynamic library 'pyp'` | file not in `extension_dir`, or wrong name (Windows: `php_pyp.dll`, Linux: `pyp.so`) |
| `Module compiled with module API=... PHP compiled with module API=...` | build for another PHP version - take the matching zip/tarball |
| `...is not a valid Win32 application` / `%1 is not a valid...` | wrong architecture, or `ts` build on `nts` PHP (or vice versa) |
| Works on CLI but not on the website | the web server uses another `php.ini` - check `phpinfo()` → *Loaded Configuration File* |

## License

MIT
