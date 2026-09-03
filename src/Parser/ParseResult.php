<?php

declare(strict_types=1);

namespace PhpSentinel\Parser;

use PhpParser\Node;
use PhpParser\Node\Stmt;

/**
 * Immutable result of parsing a single PHP source file.
 *
 * A successful parse carries the root AST statements; a failed parse carries a
 * human readable diagnostic instead. Exactly one of the two is populated, so
 * callers can inspect {@see isSuccess()} before accessing either member.
 */
final readonly class ParseResult
{
    /**
     * @param list<Stmt>|null    $ast             root statements when parsing succeeded
     * @param string|null        $error           parse error message when parsing failed
     * @param int|null           $errorLine       line of the parse error when known
     * @param int|null           $errorColumn     column of the parse error when known
     */
    public function __construct(
        public ?array $ast,
        public ?string $error,
        public ?int $errorLine,
        public ?int $errorColumn,
    ) {
    }

    /**
     * @param list<Stmt> $ast
     */
    public static function success(array $ast): self
    {
        return new self($ast, null, null, null);
    }

    public static function failure(string $error, ?int $line = null, ?int $column = null): self
    {
        return new self(null, $error, $line, $column);
    }

    public function isSuccess(): bool
    {
        return $this->ast !== null;
    }

    public function isFailure(): bool
    {
        return $this->error !== null;
    }
}
