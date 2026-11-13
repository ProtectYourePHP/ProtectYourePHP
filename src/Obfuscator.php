<?php
declare(strict_types=1);

namespace Pyp;

/**
 * Token based source transformer:
 *  - rewrites __FILE__ / __DIR__ so they keep pointing at the original location
 *  - strips comments / collapses whitespace
 *  - renames local variables per function scope
 *
 * Variables are only renamed inside function/method/closure scopes, never at file
 * level (file level variables are shared with other files and templates). Scopes
 * that use eval/include/compact/extract/$$ etc. are left alone, and parameters of
 * public API functions keep their names (named arguments).
 */
final class Obfuscator
{
    private const SUPER = [
        'this', 'GLOBALS', '_SERVER', '_GET', '_POST', '_FILES', '_COOKIE', '_SESSION',
        '_REQUEST', '_ENV', 'http_response_header', 'php_errormsg',
    ];
    private const BAIL_FUNCS = ['compact', 'extract', 'get_defined_vars', 'parse_str', 'mb_parse_str'];

    /** @var array<string,bool> */
    private array $used = [];
    /** @var string[] */
    public array $warnings = [];

    /**
     * @param array{rename_vars?:bool,strip_comments?:bool,keep_docblocks?:bool} $opt
     */
    public function transform(string $src, array $opt): string
    {
        $rename = $opt['rename_vars'] ?? true;
        $strip = $opt['strip_comments'] ?? true;
        $keepDoc = $opt['keep_docblocks'] ?? false;

        /** @var \PhpToken[] $tokens */
        $tokens = \PhpToken::tokenize($src, TOKEN_PARSE);
        $n = count($tokens);
        $this->used = [];
        foreach ($tokens as $t) {
            if ($t->id === T_VARIABLE) {
                $this->used[substr($t->text, 1)] = true;
            }
        }

        $scopes = [];
        $owner = array_fill(0, max($n, 1), -1);
        if ($rename) {
            $this->buildScopes($tokens, $scopes, $owner);
        }

        $out = [];
        $lastWs = true;
        for ($i = 0; $i < $n; $i++) {
            $t = $tokens[$i];
            if ($t->id === T_HALT_COMPILER) {
                $this->warnings[] = '__halt_compiler() data is not supported in encoded files; exclude this file';
            }
            switch ($t->id) {
                case T_COMMENT:
                case T_DOC_COMMENT:
                    if ($strip && !($keepDoc && $t->id === T_DOC_COMMENT)) {
                        // a removed comment still separates tokens ("1+/**/+2" must not become "1++2")
                        if (!$lastWs) {
                            $out[] = ' ';
                            $lastWs = true;
                        }
                        continue 2;
                    }
                    $out[] = $t->text;
                    $lastWs = false;
                    continue 2;
                case T_WHITESPACE:
                    if ($strip) {
                        if (!$lastWs) {
                            $out[] = ' ';
                            $lastWs = true;
                        }
                        continue 2;
                    }
                    break;
                case T_FILE:
                case T_DIR:
                    if (!empty($opt['native_paths'])) {
                        break;
                    }
                    if ($this->inConstContext($tokens, $i)) {
                        // stays a pyp:// path, which the loader's stream wrapper resolves for include/fopen/stat
                        $this->warnings[] = sprintf('%s in a constant expression (line %d) resolves to a pyp:// path at runtime', $t->text, $t->line);
                        break;
                    }
                    $out[] = '\\Pyp\\Loader::' . ($t->id === T_FILE ? 'file' : 'dir') . '(__FILE__)';
                    $lastWs = false;
                    continue 2;
                case T_VARIABLE:
                    if ($owner[$i] >= 0 && !$this->prevIs($tokens, $i, T_DOUBLE_COLON)) {
                        $isUse = isset($scopes[$owner[$i]]['useIdx'][$i]);
                        $name = $this->resolve($scopes, $owner[$i], substr($t->text, 1), $isUse);
                        $out[] = '$' . $name;
                        $lastWs = false;
                        continue 2;
                    }
                    break;
            }
            $out[] = $t->text;
            $lastWs = $t->id === T_WHITESPACE || $t->id === T_OPEN_TAG;
        }
        return implode('', $out);
    }

    // ------------------------------------------------------------------

    private function prevIs(array $tokens, int $i, int $id): bool
    {
        for ($j = $i - 1; $j >= 0; $j--) {
            if ($tokens[$j]->id === T_WHITESPACE || $tokens[$j]->id === T_COMMENT || $tokens[$j]->id === T_DOC_COMMENT) {
                continue;
            }
            return $tokens[$j]->id === $id;
        }
        return false;
    }

    private function nextSig(array $tokens, int $i): int
    {
        $n = count($tokens);
        for ($j = $i + 1; $j < $n; $j++) {
            if (!in_array($tokens[$j]->id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                return $j;
            }
        }
        return $n;
    }

    /** Visibility/modifier tokens incl. PHP 8.4 asymmetric visibility (public(set) ...). */
    private static function modifierIds(): array
    {
        static $ids = null;
        if ($ids === null) {
            $ids = [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_READONLY];
            foreach (['T_PUBLIC_SET', 'T_PROTECTED_SET', 'T_PRIVATE_SET'] as $c) {
                if (defined($c)) {
                    $ids[] = constant($c);
                }
            }
        }
        return $ids;
    }

    private function prevSig(array $tokens, int $i): int
    {
        for ($j = $i - 1; $j >= 0; $j--) {
            if (!in_array($tokens[$j]->id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                return $j;
            }
        }
        return -1;
    }

    /**
     * Is token $i part of a compile time constant expression (where a method call is not allowed)?
     * const / class constants, property defaults, parameter defaults, attribute arguments,
     * static variable initialisers and backed enum case values.
     */
    private function inConstContext(array $tokens, int $i): bool
    {
        $paren = 0;
        $bracket = 0;
        $sawAssign = false;
        for ($j = $i - 1; $j >= 0; $j--) {
            $t = $tokens[$j];
            $id = $t->id;
            if ($t->text === ')') {
                $paren++;
                continue;
            }
            if ($t->text === ']') {
                $bracket++;
                continue;
            }
            if ($id === T_ATTRIBUTE) {
                if ($bracket === 0) {
                    return true;   // inside #[...]
                }
                $bracket--;
                continue;
            }
            if ($t->text === '[') {
                if ($bracket > 0) {
                    $bracket--;
                }
                continue;
            }
            if ($t->text === '(') {
                if ($paren > 0) {
                    $paren--;
                    continue;
                }
                // unmatched "(": parameter list of a function declaration?
                $k = $this->prevSig($tokens, $j);
                if ($k >= 0 && $tokens[$k]->text === '&') {
                    $k = $this->prevSig($tokens, $k);
                }
                if ($k >= 0 && ($tokens[$k]->id === T_FUNCTION || $tokens[$k]->id === T_FN)) {
                    return true;
                }
                if ($k >= 0 && $tokens[$k]->id === T_STRING) {
                    $k2 = $this->prevSig($tokens, $k);
                    if ($k2 >= 0 && $tokens[$k2]->text === '&') {
                        $k2 = $this->prevSig($tokens, $k2);
                    }
                    if ($k2 >= 0 && $tokens[$k2]->id === T_FUNCTION) {
                        return true;
                    }
                }
                continue;
            }
            if ($paren > 0 || $bracket > 0) {
                continue;
            }
            if ($t->text === ';' || $t->text === '{' || $t->text === '}' || $id === T_OPEN_TAG
                || $id === T_FUNCTION || $id === T_FN) {
                return false;
            }
            if ($t->text === '=') {
                $sawAssign = true;
            } elseif ($id === T_CONST) {
                return true;
            } elseif ($id === T_CASE) {
                return $sawAssign;   // enum Foo: string { case A = __DIR__; }
            } elseif ($id === T_VAR || in_array($id, self::modifierIds(), true)) {
                return true;         // property default
            } elseif ($id === T_STATIC) {
                $k = $this->nextSig($tokens, $j);
                if (isset($tokens[$k]) && $tokens[$k]->id === T_VARIABLE) {
                    return true;     // static $x = ...;
                }
            }
        }
        return false;
    }

    private function matchClose(array $tokens, int $open): int
    {
        $n = count($tokens);
        $depth = 0;
        for ($j = $open; $j < $n; $j++) {
            $t = $tokens[$j];
            if ($t->text === '(' || $t->text === '[' || $t->text === '{' || $t->id === T_CURLY_OPEN || $t->id === T_DOLLAR_OPEN_CURLY_BRACES) {
                $depth++;
            } elseif ($t->text === ')' || $t->text === ']' || $t->text === '}') {
                $depth--;
                if ($depth === 0) {
                    return $j;
                }
            }
        }
        return $n - 1;
    }

    private function buildScopes(array $tokens, array &$scopes, array &$owner): void
    {
        $n = count($tokens);
        $stack = [];
        for ($i = 0; $i < $n; $i++) {
            while ($stack && $scopes[end($stack)]['end'] < $i) {
                array_pop($stack);
            }
            $t = $tokens[$i];
            if (($t->id === T_FUNCTION || $t->id === T_FN) && !$this->prevIs($tokens, $i, T_USE)) {
                $sc = $this->parseScope($tokens, $i);
                if ($sc !== null) {
                    $sc['parent'] = $stack ? end($stack) : -1;
                    $scopes[] = $sc;
                    $stack[] = count($scopes) - 1;
                }
            }
            $s = $stack ? end($stack) : -1;
            $owner[$i] = $s;
            if ($s < 0) {
                continue;
            }
            // constructs that make renaming unsafe in this scope
            $bail = false;
            if (in_array($t->id, [T_EVAL, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE, T_DOLLAR_OPEN_CURLY_BRACES], true)) {
                $bail = true;
            } elseif ($t->text === '$') {
                $bail = true;
            } elseif ($t->id === T_STRING && in_array(strtolower($t->text), self::BAIL_FUNCS, true)) {
                $bail = $tokens[$this->nextSig($tokens, $i)]->text === '(';
            } elseif ($t->id === T_GLOBAL) {
                for ($j = $i + 1; $j < $n && $tokens[$j]->text !== ';'; $j++) {
                    if ($tokens[$j]->id === T_VARIABLE) {
                        $scopes[$s]['fixed'][substr($tokens[$j]->text, 1)] = true;
                    }
                }
            }
            if ($bail) {
                for ($k = $s; $k >= 0; $k = ($scopes[$k]['kind'] === 'arrow' ? $scopes[$k]['parent'] : -1)) {
                    $scopes[$k]['bail'] = true;
                }
            }
        }
    }

    private function parseScope(array $tokens, int $i): ?array
    {
        $n = count($tokens);
        $arrow = $tokens[$i]->id === T_FN;
        $j = $this->nextSig($tokens, $i);
        if ($tokens[$j]->text === '&') {
            $j = $this->nextSig($tokens, $j);
        }
        $named = false;
        if (!$arrow && $tokens[$j]->text !== '(') {
            $named = true;
            $j = $this->nextSig($tokens, $j);
        }
        if (!isset($tokens[$j]) || $tokens[$j]->text !== '(') {
            return null;
        }
        $close = $this->matchClose($tokens, $j);

        $params = [];
        $promoted = [];
        $depth = 0;
        $isPromo = false;
        for ($k = $j + 1; $k < $close; $k++) {
            $t = $tokens[$k];
            if ($t->text === '(' || $t->text === '[' || $t->text === '{') {
                $depth++;
            } elseif ($t->text === ')' || $t->text === ']' || $t->text === '}') {
                $depth--;
            } elseif ($depth === 0) {
                if ($t->text === ',') {
                    $isPromo = false;
                } elseif (in_array($t->id, self::modifierIds(), true)) {
                    $isPromo = true;
                } elseif ($t->id === T_VARIABLE) {
                    $params[substr($t->text, 1)] = true;
                    if ($isPromo) {
                        $promoted[substr($t->text, 1)] = true;
                    }
                }
            }
        }

        $k = $this->nextSig($tokens, $close);
        $useIdx = [];
        $useNames = [];
        if (isset($tokens[$k]) && $tokens[$k]->id === T_USE) {
            $k = $this->nextSig($tokens, $k);
            $uc = $this->matchClose($tokens, $k);
            for ($m = $k + 1; $m < $uc; $m++) {
                if ($tokens[$m]->id === T_VARIABLE) {
                    $useIdx[$m] = true;
                    $useNames[substr($tokens[$m]->text, 1)] = true;
                }
            }
            $k = $uc + 1;
        }

        if ($arrow) {
            $depth = 0;
            for (; $k < $n; $k++) {
                $t = $tokens[$k];
                if ($t->id === T_DOUBLE_ARROW && $depth === 0) {
                    break;
                }
            }
            $end = $k;
            for ($k = $k + 1; $k < $n; $k++) {
                $t = $tokens[$k];
                if ($t->text === '(' || $t->text === '[' || $t->text === '{' || $t->id === T_CURLY_OPEN) {
                    $depth++;
                } elseif ($t->text === ')' || $t->text === ']' || $t->text === '}') {
                    if ($depth === 0) {
                        break;
                    }
                    $depth--;
                } elseif ($depth === 0 && ($t->text === ',' || $t->text === ';' || $t->id === T_CLOSE_TAG)) {
                    break;
                }
                if (!in_array($t->id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    $end = $k;
                }
            }
            $kind = 'arrow';
        } else {
            $depth = 0;
            for (; $k < $n; $k++) {
                $t = $tokens[$k];
                if ($t->text === '(') {
                    $depth++;
                } elseif ($t->text === ')') {
                    $depth--;
                } elseif ($depth === 0 && $t->text === ';') {
                    return null; // abstract / interface method
                } elseif ($depth === 0 && $t->text === '{') {
                    break;
                }
            }
            if ($k >= $n) {
                return null;
            }
            $end = $this->matchClose($tokens, $k);
            $kind = $named ? 'function' : 'closure';
        }

        $renameParams = true;
        if ($kind === 'function') {
            $renameParams = false;
            for ($b = $i - 1; $b >= 0; $b--) {
                $id = $tokens[$b]->id;
                if ($id === T_WHITESPACE || $id === T_COMMENT || $id === T_DOC_COMMENT) {
                    continue;
                }
                if ($id === T_PRIVATE) {
                    $renameParams = true;
                    break;
                }
                if (!in_array($id, [T_STATIC, T_FINAL, T_ABSTRACT, T_PUBLIC, T_PROTECTED], true)) {
                    break;
                }
            }
        }

        return [
            'start' => $i, 'end' => $end, 'kind' => $kind, 'parent' => -1,
            'params' => $params, 'promoted' => $promoted, 'renameParams' => $renameParams,
            'useIdx' => $useIdx, 'useNames' => $useNames,
            'map' => [], 'fixed' => [], 'bail' => false,
        ];
    }

    private function resolve(array &$scopes, int $s, string $name, bool $isUse): string
    {
        if (in_array($name, self::SUPER, true)) {
            return $name;
        }
        $sc = &$scopes[$s];
        if ($isUse) {
            $parent = $sc['parent'];
            $r = $parent >= 0 ? $this->resolve($scopes, $parent, $name, false) : $name;
            return $sc['map'][$name] = $r;
        }
        if (isset($sc['map'][$name])) {
            return $sc['map'][$name];
        }
        $isParam = isset($sc['params'][$name]);
        if ($sc['kind'] === 'arrow' && !$isParam) {
            $parent = $sc['parent'];
            return $sc['map'][$name] = ($parent >= 0 ? $this->resolve($scopes, $parent, $name, false) : $name);
        }
        if ($sc['kind'] === 'closure' && isset($sc['useNames'][$name]) && !$isParam) {
            $parent = $sc['parent'];
            return $sc['map'][$name] = ($parent >= 0 ? $this->resolve($scopes, $parent, $name, false) : $name);
        }
        if ($sc['bail'] || isset($sc['fixed'][$name])
            || ($isParam && (!$sc['renameParams'] || isset($sc['promoted'][$name])))) {
            return $sc['map'][$name] = $name;
        }
        return $sc['map'][$name] = $this->fresh();
    }

    private function fresh(): string
    {
        do {
            $name = '_' . substr(bin2hex(random_bytes(5)), 0, 8);
        } while (isset($this->used[$name]));
        $this->used[$name] = true;
        return $name;
    }
}
