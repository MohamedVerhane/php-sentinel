<?php

declare(strict_types=1);

namespace PhpSentinel\Discovery;

/**
 * Discovers PHP source files recursively within a set of paths.
 *
 * The discovery walks directories (and yields files given directly), filters by
 * extension, applies ignore patterns, normalizes paths, and tolerates
 * unreadable entries without aborting the scan.
 */
final class FileDiscovery
{
    /**
     * @param list<string> $extensions    file extensions to consider (no leading dot)
     * @param list<string> $ignoredPaths  path components or trailing names to ignore
     */
    public function __construct(
        private array $extensions = ['php', 'phtml', 'inc'],
        private array $ignoredPaths = ['vendor', 'node_modules', '.git', 'storage', 'cache'],
    ) {
    }

    /**
     * Discovers files within the given paths.
     *
     * Each input path may be an existing file (returned if it matches) or a
     * directory (walked recursively). Non-existent or unreadable paths are
     * skipped and collected in the returned {@see DiscoveryResult}.
     *
     * @param list<string> $paths
     */
    public function discover(array $paths): DiscoveryResult
    {
        $files = [];
        $skipped = [];

        foreach ($paths as $path) {
            $normalized = $this->normalize($path);
            $real = realpath($normalized);

            if ($real === false) {
                $skipped[] = $normalized;
                continue;
            }

            if (is_file($real)) {
                if ($this->shouldScanFile($real)) {
                    $files[] = $real;
                } else {
                    $skipped[] = $real;
                }
                continue;
            }

            if (is_dir($real)) {
                $this->walk($real, $real, $files, $skipped);
                continue;
            }
        }

        $files = array_values(array_unique($files));

        return new DiscoveryResult($files, $skipped);
    }

    /**
     * @param list<string> $files
     * @param list<string> $skipped
     */
    private function walk(string $root, string $dir, array &$files, array &$skipped): void
    {
        $entries = @scandir($dir);

        if ($entries === false) {
            $skipped[] = $dir;

            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $dir . DIRECTORY_SEPARATOR . $entry;

            if ($this->isIgnored(basename($entry))) {
                continue;
            }

            if (is_dir($path)) {
                $this->walk($root, $path, $files, $skipped);

                continue;
            }

            if (is_file($path)) {
                if ($this->shouldScanFile($path)) {
                    $files[] = $path;
                } else {
                    $skipped[] = $path;
                }
            }
        }
    }

    private function shouldScanFile(string $path): bool
    {
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        return in_array($extension, $this->normalizedExtensions(), true);
    }

    /**
     * Applies ignore rules. An entry is ignored when its basename (or any path
     * component) matches one of the configured ignored path fragments.
     */
    private function isIgnored(string $basename): bool
    {
        foreach ($this->ignoredPaths as $ignored) {
            if ($ignored === '') {
                continue;
            }

            if (strcasecmp($basename, $ignored) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalizes a path to use the platform directory separator and to collapse
     * redundant separators and `./` segments, guarding against traversal.
     */
    private function normalize(string $path): string
    {
        $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, trim($path));

        if ($path === '' || $path === '.') {
            return getcwd() ?: '.';
        }

        $path = preg_replace('#[\\\\/]{2,}#', DIRECTORY_SEPARATOR, $path) ?? $path;

        return $path;
    }

    /**
     * @return list<string>
     */
    private function normalizedExtensions(): array
    {
        $normalized = [];
        foreach ($this->extensions as $extension) {
            $normalized[] = strtolower(ltrim($extension, '.'));
        }

        return $normalized;
    }
}
