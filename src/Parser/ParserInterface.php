<?php

declare(strict_types=1);

namespace PhpSentinel\Parser;

/**
 * Parses PHP source code into an AST without ever executing it.
 */
interface ParserInterface
{
    /**
     * Parses PHP source code and returns the result.
     *
     * The implementation must never include, require, or otherwise execute the
     * provided source. Malformed input must yield a failure {@see ParseResult}
     * rather than throwing.
     *
     * @param string      $code      the raw PHP source code
     * @param string|null $fileHint  filename used only to improve diagnostics
     */
    public function parse(string $code, ?string $fileHint = null): ParseResult;
}
