<?php

declare(strict_types=1);

namespace PhpSentinel\Tests;

use PhpParser\ParserFactory;
use PhpSentinel\Config\Configuration;
use PhpSentinel\Discovery\FileDiscovery;
use PhpSentinel\Parser\PhpParser;
use PhpSentinel\Rules\RuleRegistry;
use PhpSentinel\Scanner\FileScanner;
use PhpSentinel\Scanner\Scanner;
use PhpSentinel\Support\Severity;

final class ScannerIntegrationTest extends TestCase
{
    private Scanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $registry = RuleRegistry::withDefaultRules();
        $parser = new PhpParser((new ParserFactory())->createForNewestSupportedVersion());
        $this->scanner = new Scanner(
            new FileDiscovery(),
            new FileScanner($parser),
            $registry,
        );
    }

    /**
     * @param list<string> $rules
     */
    private function config(string $path, array $rules = []): Configuration
    {
        $defaults = Configuration::defaults([$path]);

        if ($rules !== []) {
            return $defaults->with(['enabledRules' => $rules]);
        }

        return $defaults;
    }

    public function testVulnerableFixturesProduceFindingsPerFile(): void
    {
        $perFile = [
            'sql-injection-basic.php' => 'SEC001',
            'sql-injection-interpolation.php' => 'SEC001',
            'sql-injection-mysqli.php' => 'SEC001',
            'sql-injection-data-flow.php' => 'SEC001',
            'sql-injection-interpolation-quote.php' => 'SEC001',
            'xss-basic.php' => 'SEC002',
            'xss-print-concat.php' => 'SEC002',
            'xss-printf.php' => 'SEC002',
            'command-injection-basic.php' => 'SEC003',
            'command-injection-concat.php' => 'SEC003',
            'file-inclusion-basic.php' => 'SEC004',
            'file-inclusion-dynamic.php' => 'SEC004',
            'file-inclusion-prefixed.php' => 'SEC004',
            'unsafe-upload-basic.php' => 'SEC005',
        ];

        $result = $this->scanner->scan($this->config($this->fixture('vulnerable')));

        self::assertGreaterThanOrEqual(count($perFile), count($result->findings));
        self::assertSame(count($perFile), $result->filesScanned);
        self::assertSame([], $result->parseErrors);

        $byFile = [];
        foreach ($result->findings as $finding) {
            $byFile[basename($finding->file)][] = $finding->ruleId;
        }

        foreach ($perFile as $file => $ruleId) {
            self::assertArrayHasKey($file, $byFile, "Expected finding in $file");
            self::assertContains($ruleId, $byFile[$file], "Expected rule $ruleId in $file");
        }

        $this->verifyFindingShape($result->findings[0] ?? null);
    }

    public function testSafeFixturesProduceNoFindings(): void
    {
        $result = $this->scanner->scan($this->config($this->fixture('safe')));

        self::assertSame([], $result->findings, 'Safe fixtures must not trigger vulnerabilities.');
        self::assertSame(8, $result->filesScanned);
    }

    public function testFindingCarriesLocationAndMetadata(): void
    {
        $result = $this->scanner->scan($this->config($this->fixture('vulnerable/sql-injection-basic.php')));

        self::assertCount(1, $result->findings);
        $finding = $result->findings[0];

        self::assertSame('SEC001', $finding->ruleId);
        self::assertSame(Severity::HIGH, $finding->severity);
        self::assertSame('CWE-89', $finding->cwe);
        self::assertGreaterThan(0, $finding->line);
        self::assertNotEmpty($finding->codeSnippet);
        self::assertSame(
            $this->normalizeSeparators($this->fixture('vulnerable/sql-injection-basic.php')),
            $this->normalizeSeparators($finding->file),
        );
    }

    private function normalizeSeparators(string $path): string
    {
        return str_replace('\\', '/', $path);
    }

    public function testSeverityThresholdFiltersFindings(): void
    {
        $config = Configuration::defaults([$this->fixture('vulnerable')])
            ->with(['severityThreshold' => Severity::HIGH]);

        $result = $this->scanner->scan($config);

        foreach ($result->findings as $finding) {
            self::assertNotSame(Severity::MEDIUM, $finding->severity, 'MEDIUM findings should be filtered out.');
        }
    }

    public function testRulesCanBeLimited(): void
    {
        $result = $this->scanner->scan($this->config($this->fixture('vulnerable'), ['SEC001']));

        foreach ($result->findings as $finding) {
            self::assertSame('SEC001', $finding->ruleId);
        }
    }

    public function testVersionIsPropagated(): void
    {
        $this->scanner->setVersion('9.9.9');
        $result = $this->scanner->scan($this->config($this->fixture('safe')));

        self::assertSame('9.9.9', $result->version);
    }

    private function verifyFindingShape(?object $finding): void
    {
        if ($finding === null) {
            $this->fail('Expected at least one finding.');
        }
        $this->assertInstanceOf(\PhpSentinel\Support\Finding::class, $finding);
        self::assertNotEmpty($finding->ruleId);
        self::assertNotEmpty($finding->ruleName);
        self::assertNotEmpty($finding->file);
        self::assertNotEmpty($finding->codeSnippet);
    }
}
