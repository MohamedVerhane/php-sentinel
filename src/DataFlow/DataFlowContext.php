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
