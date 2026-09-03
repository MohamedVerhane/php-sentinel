<?php

declare(strict_types=1);

namespace PhpSentinel\Config;

use PhpSentinel\Exception\ConfigurationException;
use PhpSentinel\Support\Severity;

/**
 * Loads and validates a `.php-sentinel.php` configuration file.
 *
 * The configuration file must be a PHP file that returns an array of options.
 * It is the user's own trusted project configuration: unlike scanned source
 * code, the configuration file is executed in the same way Composer and other
 * CLI tools execute their project config files.
 *
 * All values are validated so that a malformed file produces a clear error
 * rather than a confusing runtime failure.
 */
final class ConfigurationLoader
{
    public const CONFIG_FILENAME = '.php-sentinel.php';

    /**
     * The options that may be set in a configuration file, mapped to their
     * expected aggregate PHP types.
     *
     * @var array<string, string>
     */
    private const OPTION_TYPES = [
        'extensions' => 'array',
        'ignore' => 'array',
        'rules' => 'array',
        'disabled_rules' => 'array',
        'severity' => 'string',
        'format' => 'string',
        'progress' => 'bool',
        'verbose' => 'bool',
    ];

    /**
     * Loads a configuration file and returns the explicitly provided options as
     * an associative array suitable for merging onto
     * {@see Configuration::defaults()} via {@see Configuration::with()}.
     *
     * Returns null when the file does not exist. Omitted options are simply
     * absent from the returned array so the caller's defaults are preserved.
     *
     * @return array<string, mixed>|null explicit overrides or null when absent
     */
    public function load(?string $path): ?array
    {
        if ($path === null || $path === '') {
            return null;
        }

        $absolute = $this->resolvePath($path);

        if (!is_file($absolute)) {
            throw new ConfigurationException(sprintf(
                'Configuration file "%s" does not exist.',
                $absolute,
            ));
        }

        $loaded = $this->requireConfigFile($absolute);

        return $this->normalize($loaded, $absolute);
    }

    /**
     * Tries the default config filename in the given directory. Returns the
     * explicit overrides array, or null when no such file exists.
     *
     * @return array<string, mixed>|null
     */
    public function loadFromDirectory(string $directory): ?array
    {
        $candidate = rtrim($directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . self::CONFIG_FILENAME;

        return is_file($candidate) ? $this->load($candidate) : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function requireConfigFile(string $path): array
    {
        try {
            $result = require $path;
        } catch (\Throwable $e) {
            throw ConfigurationException::fromThrowable(sprintf(
                'Failed to load configuration file "%s"',
                $path,
            ), $e);
        }

        if (!is_array($result)) {
            throw new ConfigurationException(sprintf(
                'Configuration file "%s" must return an array of options.',
                $path,
            ));
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $raw
     *
     * @return array<string, mixed>
     */
    private function normalize(array $raw, string $path): array
    {
        foreach (array_keys($raw) as $option) {
            if (!array_key_exists($option, self::OPTION_TYPES)) {
                throw new ConfigurationException(sprintf(
                    'Unknown configuration option "%s" in "%s".',
                    (string) $option,
                    $path,
                ));
            }
        }

        $overrides = [];

        if (array_key_exists('extensions', $raw)) {
            $overrides['extensions'] = $this->readList($raw, 'extensions', $path);
        }

        if (array_key_exists('ignore', $raw)) {
            $overrides['ignoredPaths'] = $this->readList($raw, 'ignore', $path);
        }

        if (array_key_exists('rules', $raw)) {
            $overrides['enabledRules'] = $this->readList($raw, 'rules', $path);
        }

        if (array_key_exists('disabled_rules', $raw)) {
            $disabled = $this->readList($raw, 'disabled_rules', $path);
            $enabledRules = $overrides['enabledRules'] ?? $this->defaultRuleIds();
            $overrides['enabledRules'] = array_values(array_diff($enabledRules, $disabled));
        }

        if (array_key_exists('severity', $raw)) {
            $overrides['severityThreshold'] = $this->readSeverity($raw, $path);
        }

        if (array_key_exists('format', $raw)) {
            $overrides['outputFormat'] = $this->readFormat($raw, $path);
        }

        if (array_key_exists('progress', $raw)) {
            $overrides['showProgress'] = $this->readBool($raw, 'progress', $path, true);
        }

        if (array_key_exists('verbose', $raw)) {
            $overrides['verbose'] = $this->readBool($raw, 'verbose', $path, false);
        }

        return $overrides;
    }

    /**
     * @param array<string, mixed> $raw
     *
     * @return list<string>
     */
    private function readList(array $raw, string $key, string $path): array
    {
        if (!array_key_exists($key, $raw)) {
            return [];
        }

        $value = $raw[$key];
        if (!is_array($value)) {
            throw new ConfigurationException(sprintf(
                'Configuration option "%s" in "%s" must be an array of strings.',
                $key,
                $path,
            ));
        }

        return array_map(
            static function (mixed $item) use ($key, $path): string {
                if (!is_string($item)) {
                    throw new ConfigurationException(sprintf(
                        'Configuration option "%s" in "%s" must contain only strings.',
                        $key,
                        $path,
                    ));
                }

                return $item;
            },
            $value,
        );
    }

    /**
     * @param array<string, mixed> $raw
     */
    private function readSeverity(array $raw, string $path): Severity
    {
        if (!array_key_exists('severity', $raw)) {
            return Severity::INFO;
        }

        $value = $raw['severity'];
        if (!is_string($value)) {
            throw new ConfigurationException(sprintf(
                'Configuration option "severity" in "%s" must be a string.',
                $path,
            ));
        }

        try {
            return Severity::fromName($value);
        } catch (\InvalidArgumentException $e) {
            throw new ConfigurationException(sprintf(
                'Invalid severity in "%s": %s',
                $path,
                $e->getMessage(),
            ));
        }
    }

    /**
     * @param array<string, mixed> $raw
     */
    private function readFormat(array $raw, string $path): string
    {
        if (!array_key_exists('format', $raw)) {
            return 'console';
        }

        $value = $raw['format'];
        if (!is_string($value) || !in_array($value, ['console', 'json'], true)) {
            throw new ConfigurationException(sprintf(
                'Configuration option "format" in "%s" must be "console" or "json".',
                $path,
            ));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private function readBool(array $raw, string $key, string $path, bool $default): bool
    {
        if (!array_key_exists($key, $raw)) {
            return $default;
        }

        $value = $raw[$key];
        if (!is_bool($value)) {
            throw new ConfigurationException(sprintf(
                'Configuration option "%s" in "%s" must be a boolean.',
                $key,
                $path,
            ));
        }

        return $value;
    }

    /**
     * Resolves a (potentially relative) config path against the current working
     * directory and normalizes it.
     */
    private function resolvePath(string $path): string
    {
        $trimmed = trim($path);
        if ($trimmed === '') {
            return $trimmed;
        }

        if ($this->isAbsolutePath($trimmed)) {
            return $this->normalizeSeparators($trimmed);
        }

        return $this->normalizeSeparators(getcwd() . DIRECTORY_SEPARATOR . $trimmed);
    }

    private function isAbsolutePath(string $path): bool
    {
        if (
            str_starts_with($path, DIRECTORY_SEPARATOR)
            || str_starts_with($path, '/')
            || preg_match('/^[A-Za-z]:[\\\\\/]/', $path) === 1
        ) {
            return true;
        }

        return false;
    }

    private function normalizeSeparators(string $path): string
    {
        return str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $path);
    }

    /**
     * @return list<string>
     */
    private function defaultRuleIds(): array
    {
        return [
            \PhpSentinel\Rules\SqlInjectionRule::ID,
            \PhpSentinel\Rules\XssRule::ID,
            \PhpSentinel\Rules\CommandInjectionRule::ID,
            \PhpSentinel\Rules\FileInclusionRule::ID,
            \PhpSentinel\Rules\UnsafeUploadRule::ID,
        ];
    }
}
