<?php

declare(strict_types=1);

namespace PhpSentinel\Scanner;

use PhpSentinel\Config\Configuration;
use PhpSentinel\Discovery\FileDiscovery;
use PhpSentinel\Rules\RuleInterface;
use PhpSentinel\Rules\RuleRegistry;
use PhpSentinel\Support\Finding;

/**
 * Orchestrates a complete scan.
 *
 * The scanner combines file discovery, parsing, rule execution and finding
 * filtering into a single pass, producing an aggregate {@see ScanResult}. It is
 * the entry point used by the CLI (and can be driven by tests directly).
 */
final class Scanner
{
    private string $version = 'dev';

    public function __construct(
        private readonly FileScanner $fileScanner,
        private readonly RuleRegistry $registry,
    ) {
    }

    public function setVersion(string $version): void
    {
        $this->version = $version;
    }

    public function version(): string
    {
        return $this->version;
    }

    /**
     * Runs a scan according to the given configuration.
     *
     * @param callable(int $done, int $total): void|null $onProgress invoked as files are scanned
     */
    public function scan(Configuration $config, ?callable $onProgress = null): ScanResult
    {
        $start = microtime(true);

        $enabledRules = $this->registry->enabled($config->enabledRules);
        $discovery = new FileDiscovery($config->extensions, $config->ignoredPaths);
        $discoveryResult = $discovery->discover($config->paths);

        $total = count($discoveryResult->files());
        $done = 0;
        $filesScanned = 0;
        $parseErrors = [];
        $allFindings = [];

        foreach ($discoveryResult->files() as $file) {
            $result = $this->fileScanner->scanFile($file, $enabledRules);
            $filesScanned++;

            if ($result->hasParseError()) {
                $parseErrors[$result->file] = (string) $result->parseError;
            } else {
                foreach ($result->findings as $finding) {
                    $allFindings[] = $finding;
                }
            }

            $done++;
            if ($onProgress !== null) {
                $onProgress($done, $total);
            }
        }

        $filtered = array_values(array_filter(
            $allFindings,
            static fn (Finding $finding): bool => $finding->meetsThreshold($config->severityThreshold),
        ));

        $filesSkipped = count($discoveryResult->skipped()) + count($parseErrors);
        $duration = microtime(true) - $start;

        return new ScanResult(
            findings: $filtered,
            filesScanned: $filesScanned,
            filesSkipped: $filesSkipped,
            parseErrors: $parseErrors,
            duration: $duration,
            version: $this->version,
            paths: $config->paths,
        );
    }

    /**
     * Returns the list of rules that would run for a given configuration.
     *
     * @return list<RuleInterface>
     */
    public function rulesFor(Configuration $config): array
    {
        return $this->registry->enabled($config->enabledRules);
    }
}
