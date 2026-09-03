<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpSentinel\DataFlow\TaintAnalyzer;

/**
 * Immutable bundle of state handed to a rule for every node it analyzes.
 *
 * The context provides the analyzer (used to resolve taint), the source code of
 * the file being scanned (used to build snippets) and the full AST.
 */
final readonly class RuleContext
{
    /**
     * @param list<Node> $ast the parsed statements of the current file
     */
    public function __construct(
        public string $file,
        public string $sourceCode,
        public TaintAnalyzer $analyzer,
        public array $ast,
    ) {
    }

    /**
     * Returns a trimmed source snippet for the given 1-based line, or null when
     * the line is out of range.
     */
    public function snippet(int $line): ?string
    {
        $lines = explode("\n", $this->sourceCode);
        if ($line < 1 || $line > count($lines)) {
            return null;
        }

        $snippet = trim($lines[$line - 1]);

        return $snippet === '' ? null : $snippet;
    }

    /**
     * Computes the 1-based column from a 0-based byte offset within the source.
     */
    public function columnAt(int $byteOffset): int
    {
        if ($byteOffset < 0) {
            return 1;
        }

        $lineStart = strrpos(substr($this->sourceCode, 0, $byteOffset), "\n");
        if ($lineStart === false) {
            return $byteOffset + 1;
        }

        return $byteOffset - $lineStart;
    }
}
