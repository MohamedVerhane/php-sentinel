<?php

declare(strict_types=1);

namespace PhpSentinel\Scanner;

use PhpSentinel\Support\Finding;

/**
 * Immutable result of scanning a single file.
 *
 * When parsing fails, {@see $findings} is empty and {@see $parseError} carries
 * a diagnostic; a parse failure must never abort the whole scan.
 */
final readonly class FileScanResult
{
    /**
     * @param list<Finding> $findings
     */
    public function __construct(
        public string $file,
        public array $findings,
        public ?string $parseError,
    ) {
    }

    public function hasParseError(): bool
    {
        return $this->parseError !== null;
    }
}
