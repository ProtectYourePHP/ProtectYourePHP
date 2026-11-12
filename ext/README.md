# PYP extension (`pyp`)

Native PHP extension for **PYP (ProtectYourePHP)**, the open source PHP encoder and
licensing system. The PYP loader works without it; when installed, the loader detects it and
uses its native helpers.

> This repository is split from [`ProtectYourePHP/ProtectYourePHP`](https://github.com/ProtectYourePHP/ProtectYourePHP)
> (`ext/`). Please open pull requests there.

## Install

```bash
pie install protectyourephp/pyp-ext
```

[PIE](https://github.com/php/pie) builds the extension (Linux/macOS) or downloads the
prebuilt DLL (Windows) and enables `extension=pyp` in your `php.ini`.

From source:

```bash
phpize
./configure --enable-pyp
make && make test TESTS=tests NO_INTERACTION=1
sudo make install        # then add extension=pyp to php.ini
```

## API (0.1.0)

| | |
|---|---|
| `pyp_macs(): array` | MAC addresses of all non-loopback interfaces (`aa:bb:cc:dd:ee:ff`), no `exec()` needed |
| `pyp_ext_info(): array` | `version`, `loader_api`, `features` |
| `PYP_EXT_VERSION`, `PYP_LOADER_API` | constants |

Supported: PHP 8.1 - 8.5, NTS and ZTS, Linux, macOS, Windows.

## Roadmap

`loader_api` 2 adds a `zend_compile_file` hook that decrypts PYP files in C, so decrypted
source never reaches userland and OPcache can cache protected code. See
[docs/native-extension.md](https://github.com/ProtectYourePHP/ProtectYourePHP/blob/main/docs/native-extension.md).

## License

MIT
