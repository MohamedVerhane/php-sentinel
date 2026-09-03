<?php

declare(strict_types=1);

namespace PhpSentinel\Tests\Discovery;

use PhpSentinel\Discovery\FileDiscovery;
use PhpSentinel\Tests\TestCase;

final class FileDiscoveryTest extends TestCase
{
    public function testDiscoversPhpFilesRecursively(): void
    {
        $discovery = new FileDiscovery();
        $result = $discovery->discover([$this->fixture('safe')]);

        self::assertNotEmpty($result->files);
        self::assertCount(8, $result->files);
        self::assertSame([], $result->skipped);
        self::assertEveryFileIsARealPhpFile($result->files);
    }

    public function testIgnoreBareNameSkipsDirectoriesByComponent(): void
    {
        $discovery = new FileDiscovery(['php'], ['safe']);
        $result = $discovery->discover([$this->fixturesDir]);

        self::assertCount(14, $result->files);
        self::assertNoPathContains($result->files, DIRECTORY_SEPARATOR . 'safe' . DIRECTORY_SEPARATOR);
    }

    public function testIgnoreRelativePathSkipsSubtree(): void
    {
        $discovery = new FileDiscovery(['php'], ['tests/Fixtures/safe']);
        $result = $discovery->discover([$this->fixturesDir]);

        self::assertCount(14, $result->files);
        self::assertNoPathContains($result->files, DIRECTORY_SEPARATOR . 'safe' . DIRECTORY_SEPARATOR);
    }

    public function testIgnoreGlobSkipsMatchingFiles(): void
    {
        $discovery = new FileDiscovery(['php'], ['tests/Fixtures/vulnerable/sql-*.php']);
        $result = $discovery->discover([$this->fixture('vulnerable')]);

        self::assertCount(9, $result->files);
        self::assertNoPathContains($result->files, 'sql-');
    }

    public function testOnlyConfiguredExtensionsAreScanned(): void
    {
        $discovery = new FileDiscovery(['txt'], []);
        $result = $discovery->discover([$this->fixture('vulnerable')]);

        self::assertSame([], $result->files);
        self::assertNotEmpty($result->skipped);
    }

    public function testNonExistentPathIsReportedAsSkipped(): void
    {
        $discovery = new FileDiscovery();
        $result = $discovery->discover(['tests/does-not-exist']);

        self::assertSame([], $result->files);
        self::assertSame(['tests' . DIRECTORY_SEPARATOR . 'does-not-exist'], $result->skipped);
    }

    /**
     * @param list<string> $files
     */
    private static function assertEveryFileIsARealPhpFile(array $files): void
    {
        foreach ($files as $file) {
            self::assertFileExists($file);
            self::assertSame('php', strtolower(pathinfo($file, PATHINFO_EXTENSION)));
        }
    }

    /**
     * @param list<string> $paths
     */
    private static function assertNoPathContains(array $paths, string $needle): void
    {
        foreach ($paths as $path) {
            self::assertStringNotContainsString($needle, $path);
        }
    }
}
