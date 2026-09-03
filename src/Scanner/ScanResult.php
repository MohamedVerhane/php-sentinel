<?php

declare(strict_types=1);

namespace PhpSentinel\Scanner;

use PhpSentinel\Support\Finding;

/**
 * Immutable aggregate result of a full scan.
 *
 * Contains the collected findings (already filtered by severity), counts of
 * scanned and skipped files, any parse diagnostics, the duration and the
 * scanner version used to produce the result.
 */
final readonly class ScanResult
{
    /**
     * @param list<Finding>        $findings     findings that meet the severity threshold
     * @param array<string,string>  $parseErrors  file path => parse diagnostic
     * @param list<string>          $paths        the paths that were scanned
     */
    public function __construct(
        public array $findings,
        public int $filesScanned,
        public int $filesSkipped,
        public array $parseErrors,
        public float $duration,
        public string $version,
        public array $paths = [],
    ) {
    }

    /**
     * @return list<Finding>
     */
    public function findings(): array
    {
        return $this->findings;
    }

    /**
     * @return array<string, string>
     */
    public function parseErrors(): array
    {
        return $this->parseErrors;
    }

    public function hasFindings(): bool
    {
        return $this->findings !== [];
    }

    /**
     * Returns a count of findings grouped by severity label.
     *
     * @return array<string, int>
     */
    public function summary(): array
    {
        $summary = [
            'info' => 0,
            'low' => 0,
            'medium' => 0,
            'high' => 0,
            'critical' => 0,
        ];

        foreach ($this->findings as $finding) {
            $key = strtolower($finding->severity->value);
            $summary[$key] = ($summary[$key] ?? 0) + 1;
        }

        return $summary;
    }
}
