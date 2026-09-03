<?php

declare(strict_types=1);

namespace PhpSentinel\Discovery;

/**
 * Immutable result of a file discovery operation.
 *
 * @phpstan-type PathList list<string>
 */
final readonly class DiscoveryResult
{
    /**
     * @param list<string> $files    absolute paths of files to scan
     * @param list<string> $skipped  paths that were excluded or unreadable
     */
    public function __construct(
        public array $files,
        public array $skipped,
    ) {
    }

    /**
     * @return list<string>
     */
    public function files(): array
    {
        return $this->files;
    }

    /**
     * @return list<string>
     */
    public function skipped(): array
    {
        return $this->skipped;
    }
}
