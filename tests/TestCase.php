<?php

declare(strict_types=1);

namespace PhpSentinel\Tests;

use PhpParser\ParserFactory;
use PhpSentinel\DataFlow\DataFlowContext;
use PhpSentinel\DataFlow\Sanitizer;
use PhpSentinel\DataFlow\TaintAnalyzer;
use PhpSentinel\Discovery\FileDiscovery;
use PhpSentinel\Parser\PhpParser;
use PhpSentinel\Rules\RuleContext;
use PhpSentinel\Rules\RuleEngine;
use PhpSentinel\Rules\RuleRegistry;
use PhpSentinel\Support\Finding;
use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected string $fixturesDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixturesDir = dirname(__DIR__) . '/tests/Fixtures';
    }

    /**
     * Parses and analyzes a single code string with the rules whose IDs are
     * given, returning the produced findings.
     *
     * @param list<string> $ruleIds
     *
     * @return list<Finding>
     */
    protected function analyzeCode(string $code, array $ruleIds): array
    {
        $factory = new ParserFactory();
        $parser = new PhpParser($factory->createForNewestSupportedVersion());
        $parseResult = $parser->parse($code, 'memory');

        self::assertTrue($parseResult->isSuccess(), 'Fixture code failed to parse: ' . ($parseResult->error ?? ''));

        $ast = $parseResult->ast ?? [];
        $sanitizers = [];
        foreach (Sanitizer::FUNCTIONS as $category => $functions) {
            $sanitizers[] = new Sanitizer($category, $functions);
        }
        $context = new DataFlowContext('memory', $sanitizers);
        $analyzer = new TaintAnalyzer($context);
        $analyzer->analyze($ast);

        $registry = RuleRegistry::withDefaultRules();
        $rules = $registry->enabled($ruleIds);
        $engine = new RuleEngine($rules);

        return $engine->run(
            $ast,
            new RuleContext('memory', $code, $analyzer, $ast),
        );
    }

    /**
     * Returns the findings produced by a single named rule for the given code.
     *
     * @return list<Finding>
     */
    protected function analyzeWithRule(string $code, string $ruleId): array
    {
        return $this->analyzeCode($code, [$ruleId]);
    }

    protected function fixture(string $relativePath): string
    {
        return $this->fixturesDir . '/' . ltrim($relativePath, '/');
    }

    /**
     * Asserts that exactly one finding exists and returns it.
     *
     * @param list<Finding> $findings
     */
    protected function assertSingleFinding(array $findings, string $ruleId): Finding
    {
        self::assertCount(1, $findings, 'Expected exactly one finding.');
        $finding = $findings[0];
        self::assertSame($ruleId, $finding->ruleId);

        return $finding;
    }
}
