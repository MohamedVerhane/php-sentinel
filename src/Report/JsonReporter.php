<?php

declare(strict_types=1);

namespace PhpSentinel\Report;

use PhpSentinel\Scanner\ScanResult;

/**
 * Renders a {@see ScanResult} as a JSON document.
 *
 * The entire output is a single valid JSON object. No human-readable console
 * text is mixed in, which makes the output suitable for piping into tools and
 * CI pipelines. Encoding failures raise a runtime error rather than emitting
 * malformed JSON.
 */
final class JsonReporter implements ReporterInterface
{
    public function render(ScanResult $result): string
    {
        $data = [
            'version' => $result->version,
            'files_scanned' => $result->filesScanned,
            'files_skipped' => $result->filesSkipped,
            'duration' => round($result->duration, 4),
            'paths' => $result->paths,
            'errors' => $result->parseErrors,
            'findings' => array_map(
                static fn ($finding) => [
                    'rule_id' => $finding->ruleId,
                    'rule_name' => $finding->ruleName,
                    'severity' => $finding->severity->value,
                    'title' => $finding->title,
                    'message' => $finding->message,
                    'description' => $finding->description,
                    'recommendation' => $finding->recommendation,
                    'cwe' => $finding->cwe,
                    'file' => $finding->file,
                    'line' => $finding->line,
                    'column' => $finding->column,
                    'code' => $finding->codeSnippet,
                ],
                $result->findings,
            ),
            'summary' => $result->summary(),
        ];

        return (string) json_encode(
            $data,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        ) . "\n";
    }
}
