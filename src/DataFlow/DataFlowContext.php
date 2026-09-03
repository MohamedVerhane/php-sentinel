<?php

declare(strict_types=1);

namespace PhpSentinel\DataFlow;

/**
 * Mutable per-file backing store for the {@see TaintAnalyzer}.
 *
 * For every variable the context tracks the set of user-controlled sources that
 * taint it and the set of sink categories for which it has been sanitized.
 * Because sanitizers are category aware (e.g. `htmlspecialchars()` neutralises
 * XSS but not command injection), sanitization is tracked per category.
 *
 * A context belongs to a single scanned file and is never shared across files,
 * keeping each scan isolated and free of global state.
 */
final class DataFlowContext
{
    /**
     * @var array<string, array{taintedSources: list<string>, sanitizedFor: list<string>}>
     */
    private array $variables = [];

    /**
     * @param list<Sanitizer> $sanitizers registered sanitizers
     */
    public function __construct(
        public readonly string $file,
        public readonly array $sanitizers = [],
    ) {
    }

    /**
     * Returns true when the variable is tainted and not sanitized for the
     * given sink category.
     */
    public function isDangerous(string $variable, string $category): bool
    {
        $entry = $this->entry($variable);

        if ($entry['taintedSources'] === []) {
            return false;
        }

        return !in_array($category, $entry['sanitizedFor'], true);
    }

    /**
     * @return list<string>
     */
    public function taintedSources(string $variable): array
    {
        return $this->entry($variable)['taintedSources'];
    }

    /**
     * @return list<string>
     */
    public function sanitizedFor(string $variable): array
    {
        return $this->entry($variable)['sanitizedFor'];
    }

    /**
     * Replaces the entire taint state of a variable.
     *
     * @param list<string> $taintedSources
     * @param list<string> $sanitizedFor
     */
    public function set(string $variable, array $taintedSources, array $sanitizedFor): void
    {
        $this->variables[$variable] = [
            'taintedSources' => array_values(array_unique($taintedSources)),
            'sanitizedFor' => array_values(array_unique($sanitizedFor)),
        ];
    }

    /**
     * Cleared the recorded state for a variable (used for fresh scopes).
     */
    public function forget(string $variable): void
    {
        unset($this->variables[$variable]);
    }

    public function reset(): void
    {
        $this->variables = [];
    }

    /**
     * Returns a raw snapshot of the current variable state, suitable for later
     * restoration with {@see restore()}.
     *
     * @return array<string, array{taintedSources: list<string>, sanitizedFor: list<string>}>
     */
    public function snapshot(): array
    {
        return $this->variables;
    }

    /**
     * Replaces the whole variable state with a snapshot produced by
     * {@see snapshot()}. Used to isolate nested scopes (branches, functions).
     *
     * @param array<string, array{taintedSources: list<string>, sanitizedFor: list<string>}> $state
     */
    public function restore(array $state): void
    {
        $this->variables = $state;
    }

    /**
     * Computes a must-taint merge across a set of branch-path states.
     *
     * Each element of `$paths` is a snapshot as produced by {@see snapshot()}
     * (a variable-name => entry map). Only variables that are defined with an
     * identical entry on every path are carried into the merged result. A
     * variable that is clean on one path but tainted on another is not
     * propagated, which avoids reporting findings derived from a single branch.
     *
     * @param list<array<string, array{taintedSources: list<string>, sanitizedFor: list<string>}>> $paths
     *
     * @return array<string, array{taintedSources: list<string>, sanitizedFor: list<string>}>
     */
    public static function mergeStates(array $paths): array
    {
        if ($paths === []) {
            return [];
        }

        $variableNames = [];
        foreach ($paths as $state) {
            foreach (array_keys($state) as $name) {
                $variableNames[$name] = true;
            }
        }

        $merged = [];
        foreach (array_keys($variableNames) as $variable) {
            $entries = [];
            $presentCount = 0;

            foreach ($paths as $state) {
                if (!array_key_exists($variable, $state)) {
                    continue;
                }
                $presentCount++;
                $entries[] = $state[$variable];
            }

            if ($presentCount === 0) {
                continue;
            }

            // A variable that is only defined on a single branch of a multi-way
            // structure is not carried past it: its value is undefined on the
            // other path(s), so carrying it would create false positives for
            // assignments that happen in just one branch.
            if ($presentCount === 1 && count($paths) > 1) {
                continue;
            }

            // The variable is carried only when it holds an identical entry on
            // every path that defines it, which is what makes the taint a
            // must-taint on the merge point. If any defining path yields a
            // different entry (e.g. a clean value), the variable is dropped.
            $allIdentical = true;
            $first = $entries[0];
            foreach ($entries as $entry) {
                if ($entry !== $first) {
                    $allIdentical = false;
                    break;
                }
            }

            if ($allIdentical) {
                $merged[$variable] = $first;
            }
        }

        return $merged;
    }

    public function hasSanitizerFor(string $functionName, string $category): bool
    {
        foreach ($this->sanitizers as $sanitizer) {
            if ($sanitizer->category === $category && $sanitizer->handles($functionName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the categories that a registered sanitizer function handles.
     *
     * @return list<string>
     */
    public function sanitizerCategoriesFor(string $functionName): array
    {
        $categories = [];
        foreach ($this->sanitizers as $sanitizer) {
            if ($sanitizer->handles($functionName)) {
                $categories[] = $sanitizer->category;
            }
        }

        return $categories;
    }

    /**
     * @return array{taintedSources: list<string>, sanitizedFor: list<string>}
     */
    public function entry(string $variable): array
    {
        return $this->variables[$variable] ?? ['taintedSources' => [], 'sanitizedFor' => []];
    }
}
