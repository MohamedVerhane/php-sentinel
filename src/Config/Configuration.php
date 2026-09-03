<?php

declare(strict_types=1);

namespace PhpSentinel\Config;

use PhpSentinel\Support\Severity;

/**
 * Immutable, resolved scanner configuration.
 *
 * The configuration combines defaults from {@see Configuration::defaults()},
 * values loaded from a `.php-sentinel.php` file (via {@see ConfigurationLoader})
 * and CLI overrides (applied by the {@see \PhpSentinel\Command\ScanCommand}).
 */
final readonly class Configuration
{
    /**
     * Default file extensions that are considered for scanning.
     *
     * @var list<string>
     */
    public const DEFAULT_EXTENSIONS = ['php', 'phtml', 'inc'];

    /**
     * Directories and file names ignored by default.
     *
     * @var list<string>
     */
    public const DEFAULT_IGNORED_PATHS = ['vendor', 'node_modules', '.git', 'storage', 'cache'];

    /**
     * @param list<string>   $paths              paths (files or directories) to scan
     * @param list<string>   $enabledRules       rule IDs that are enabled
     * @param list<string>   $extensions         file extensions to consider (no leading dot)
     * @param list<string>   $ignoredPaths       path components or suffixes to ignore
     * @param string         $outputFormat       'console' or 'json'
     * @param Severity       $severityThreshold  findings below this are filtered out
     * @param bool           $showProgress       whether to render a progress bar
     * @param bool           $verbose            whether to print debug/diagnostic output
     * @param positive-int   $maxConcurrency     reserved for future parallel scans (unused)
     */
    public function __construct(
        public array $paths = [],
        public array $enabledRules = [],
        public array $extensions = self::DEFAULT_EXTENSIONS,
        public array $ignoredPaths = self::DEFAULT_IGNORED_PATHS,
        public string $outputFormat = 'console',
        public Severity $severityThreshold = Severity::INFO,
        public bool $showProgress = true,
        public bool $verbose = false,
        public int $maxConcurrency = 1,
    ) {
    }

    /**
     * Returns a configuration populated with the bundled default rules enabled.
     *
     * @param list<string> $paths
     */
    public static function defaults(array $paths = []): self
    {
        $defaultRules = [
            \PhpSentinel\Rules\SqlInjectionRule::ID,
            \PhpSentinel\Rules\XssRule::ID,
            \PhpSentinel\Rules\CommandInjectionRule::ID,
            \PhpSentinel\Rules\FileInclusionRule::ID,
            \PhpSentinel\Rules\UnsafeUploadRule::ID,
        ];

        return new Configuration(paths: $paths, enabledRules: $defaultRules);
    }

    /**
     * Returns a copy of this configuration with the given properties replaced.
     *
     * @param array<string, mixed> $overrides keys are property names
     */
    public function with(array $overrides): self
    {
        return new self(
            paths: $overrides['paths'] ?? $this->paths,
            enabledRules: $overrides['enabledRules'] ?? $this->enabledRules,
            extensions: $overrides['extensions'] ?? $this->extensions,
            ignoredPaths: $overrides['ignoredPaths'] ?? $this->ignoredPaths,
            outputFormat: $overrides['outputFormat'] ?? $this->outputFormat,
            severityThreshold: $overrides['severityThreshold'] ?? $this->severityThreshold,
            showProgress: $overrides['showProgress'] ?? $this->showProgress,
            verbose: $overrides['verbose'] ?? $this->verbose,
            maxConcurrency: $overrides['maxConcurrency'] ?? $this->maxConcurrency,
        );
    }
}
