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
     * @param list<string> $ignoredPaths  names, relative path patterns, or globs to ignore
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
                $baseRel = $this->relativeToBase(getcwd() ?: $real, $real);
                $this->walk($real, $real, $baseRel, $files, $skipped);
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
    private function walk(string $root, string $dir, string $relDir, array &$files, array &$skipped): void
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
            $relPath = $relDir === '' ? $entry : $relDir . '/' . $entry;

            if ($this->isIgnored($relPath)) {
                continue;
            }

            if (is_dir($path)) {
                $this->walk($root, $path, $relPath, $files, $skipped);

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
     * Applies ignore rules against an entry's path relative to the walk root.
     *
     * A pattern is matched when any of the following holds:
     *
     *  1. It is a bare name (no `/`) equal to any single path component.
     *  2. It contains `/` and equals the relative path or is a leading subtree
     *     of it, or is a trailing path fragment of it (e.g. `tests/Fixtures`).
     *  3. It contains a glob wildcard (`*`, `?`, `[`) and {@see fnmatch()}
     *     matches the relative path.
     */
    private function isIgnored(string $relPath): bool
    {
        $relPath = str_replace('\\', '/', $relPath);
        $lowerRel = strtolower($relPath);

        foreach ($this->ignoredPaths as $ignored) {
            $ignored = trim($ignored);
            if ($ignored === '') {
                continue;
            }
            $pattern = str_replace('\\', '/', $ignored);

            if (strpbrk($pattern, '*?[') !== false) {
                if (fnmatch($pattern, $relPath, FNM_CASEFOLD | FNM_PATHNAME)) {
                    return true;
                }

                continue;
            }

            if (!str_contains($pattern, '/')) {
                foreach (explode('/', $relPath) as $component) {
                    if (strcasecmp($component, $pattern) === 0) {
                        return true;
                    }
                }

                continue;
            }

            $pattern = trim($pattern, '/');
            $lowerPattern = strtolower($pattern);

            // Exact match, leading subtree, or trailing fragment of the path.
            if ($lowerRel === $lowerPattern) {
                return true;
            }
            if (str_starts_with($lowerRel, $lowerPattern . '/')) {
                return true;
            }
            if (str_ends_with($lowerRel, '/' . $lowerPattern)) {
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
     * Returns the path of `$path` relative to `$base`, using forward slashes,
     * so that ignore patterns can be interpreted relative to the working
     * directory. Falls back to the leaf name when the path is not inside the
     * base.
     */
    private function relativeToBase(string $base, string $path): string
    {
        $base = rtrim(str_replace('\\', '/', $base), '/');
        $path = str_replace('\\', '/', $path);

        if ($base !== '' && strncasecmp($path, $base . '/', strlen($base) + 1) === 0) {
            return substr($path, strlen($base) + 1);
        }

        return basename($path);
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
