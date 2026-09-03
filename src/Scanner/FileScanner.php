<?php

declare(strict_types=1);

namespace PhpSentinel\Scanner;

use PhpSentinel\DataFlow\DataFlowContext;
use PhpSentinel\DataFlow\Sanitizer;
use PhpSentinel\DataFlow\TaintAnalyzer;
use PhpSentinel\Parser\ParserInterface;
use PhpSentinel\Rules\RuleContext;
use PhpSentinel\Rules\RuleEngine;
use PhpSentinel\Rules\RuleInterface;

/**
 * Scans a single PHP file: reads it, parses it into an AST, runs the enabled
 * rules and returns the findings.
 *
 * The scanner only reads and parses source code. It never includes, requires,
 * or executes the scanned file under any circumstances.
 */
final class FileScanner
{
    public function __construct(
        private readonly ParserInterface $parser,
    ) {
    }

    /**
     * @param list<RuleInterface> $enabledRules
     */
    public function scanFile(string $path, array $enabledRules): FileScanResult
    {
        $source = $this->readSource($path);
        if ($source === null) {
            return new FileScanResult($path, [], 'Unable to read file.');
        }

        $parseResult = $this->parser->parse($source, $path);

        if ($parseResult->isFailure()) {
            return new FileScanResult($path, [], $parseResult->error);
        }

        $ast = $parseResult->ast ?? [];
        $context = new DataFlowContext($path, $this->buildSanitizers());
        $analyzer = new TaintAnalyzer($context);
        $analyzer->analyze($ast);

        $engine = new RuleEngine($enabledRules);
        $findings = $engine->run(
            $ast,
            new RuleContext(
                file: $path,
                sourceCode: $source,
                analyzer: $analyzer,
                ast: $ast,
            ),
        );

        return new FileScanResult($path, $findings, null);
    }

    /**
     * Reads a file's source code, returning null when it cannot be read.
     */
    private function readSource(string $path): ?string
    {
        try {
            if (!is_file($path) || !is_readable($path)) {
                return null;
            }

            $content = file_get_contents($path);
        } catch (\Throwable) {
            return null;
        }

        return $content === false ? null : $content;
    }

    /**
     * @return list<Sanitizer>
     */
    private function buildSanitizers(): array
    {
        $sanitizers = [];
        foreach (Sanitizer::FUNCTIONS as $category => $functions) {
            $sanitizers[] = new Sanitizer($category, $functions);
        }

        return $sanitizers;
    }
}
