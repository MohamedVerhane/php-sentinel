<?php

declare(strict_types=1);

namespace PhpSentinel\DataFlow;

/**
 * Immutable taint descriptor for a value flowing through a program.
 *
 * A value is either clean or tainted. When tainted it records the names of the
 * user-controlled sources (for example `$_GET`) from which it originated. The
 * sanitized state is intentionally NOT stored here — sanitization is category
 * aware (see {@see DataFlowContext}) because a sanitizer such as
 * `htmlspecialchars()` neutralises XSS but not command injection.
 */
final readonly class Taint
{
    /**
     * @param list<string> $sources names of the user-controlled sources
     */
    public function __construct(
        public bool $tainted,
        public array $sources = [],
    ) {
    }

    public static function clean(): self
    {
        return new self(false);
    }

    public static function tainted(string ...$sources): self
    {
        return new self(true, array_values($sources));
    }

    /**
     * Returns true when the value is tainted and not sanitized for the given
     * sink category.
     *
     * @param list<string> $sanitizedFor categories for which the value is safe
     */
    public function isDangerousFor(string $category, array $sanitizedFor = []): bool
    {
        if (!$this->tainted) {
            return false;
        }

        return !in_array($category, $sanitizedFor, true);
    }

    /**
     * Returns the union of two taint states: dangerous when either operand is
     * dangerous, sourcing the merged sources.
     */
    public static function merge(self $left, self $right): self
    {
        return new self(
            $left->tainted || $right->tainted,
            array_values(array_unique(array_merge($left->sources, $right->sources))),
        );
    }
}
