<?php

declare(strict_types=1);

namespace PhpSentinel\DataFlow;

/**
 * Describes a dangerous sink — a place where user-controlled data, if it
 * reaches here un-sanitized, can cause a security vulnerability.
 *
 * A sink identifies function calls and method calls by name. The category is
 * used to match the appropriate sanitizer (for example escaped HTML output is
 * safe for an XSS sink but not for a command sink).
 */
final readonly class Sink
{
    /**
     * @param list<string> $functionNames lower-case function names (e.g. 'exec')
     * @param list<string> $methodNames   method names (e.g. 'query', 'exec')
     */
    public function __construct(
        public string $category,
        public array $functionNames = [],
        public array $methodNames = [],
    ) {
    }

    /**
     * Returns true when the given lower-cased function name is a sink.
     */
    public function matchesFunction(string $functionName): bool
    {
        return in_array(strtolower($functionName), $this->functionNames, true);
    }

    /**
     * Returns true when the given method name is a sink.
     */
    public function matchesMethod(string $methodName): bool
    {
        return in_array(strtolower($methodName), $this->methodNames, true);
    }
}
