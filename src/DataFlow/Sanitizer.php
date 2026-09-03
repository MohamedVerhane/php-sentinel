<?php

declare(strict_types=1);

namespace PhpSentinel\DataFlow;

/**
 * Describes a function (or method) that neutralises user-controlled data.
 *
 * When tainted data passes through a recognised sanitizer the result is marked
 * sanitized and is no longer reported as dangerous for sinks of the matching
 * category. Sanitizers are category aware: for example `htmlspecialchars()`
 * neutralises XSS but does not neutralise SQL injection.
 */
final readonly class Sanitizer
{
    /**
     * The function names that are considered sanitizing functions, grouped by
     * sink category.
     *
     * @var array<string, list<string>>
     */
    public const FUNCTIONS = [
        'xss' => ['htmlspecialchars', 'htmlentities'],
        'sql' => [],
        'command' => ['escapeshellarg', 'escapeshellcmd'],
        'file-inclusion' => [],
    ];

    /**
     * @param list<string> $functionNames
     */
    public function __construct(
        public string $category,
        public array $functionNames,
    ) {
    }

    public function handles(string $functionName): bool
    {
        return in_array(strtolower($functionName), $this->functionNames, true);
    }

    /**
     * Returns true when the given function name is a sanitizer for any category
     * and returns which categories it sanitizes.
     *
     * @return list<string> the categories that this function sanitizes
     */
    public static function categoriesHandledBy(string $functionName): array
    {
        $lower = strtolower($functionName);
        $categories = [];

        foreach (self::FUNCTIONS as $category => $names) {
            if (in_array($lower, $names, true)) {
                $categories[] = $category;
            }
        }

        return $categories;
    }
}
