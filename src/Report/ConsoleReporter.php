<?php

declare(strict_types=1);

namespace PhpSentinel\Report;

use PhpSentinel\Scanner\ScanResult;
use PhpSentinel\Support\Finding;
use PhpSentinel\Support\Severity;

/**
 * Renders a {@see ScanResult} as a human-readable console report.
 *
 * The output is plain text (no ANSI escape sequences) so that it is easy to
 * capture in logs and CI. Findings are grouped by severity and listed with
 * their location, snippet and message.
 */
final class ConsoleReporter implements ReporterInterface
{
    private const RULE = '────────────────────────────────────────';

    public function render(ScanResult $result): string
    {
        $lines = [];
        $lines[] = 'PHP Sentinel';
        $lines[] = self::RULE;
        $lines[] = '';

        $paths = $result->paths !== [] ? implode(', ', $result->paths) : '.';
        $lines[] = 'Scanning: ' . $paths;
        $lines[] = '';
        $lines[] = sprintf('Files scanned: %d', $result->filesScanned);
        $lines[] = sprintf('Files skipped: %d', $result->filesSkipped);
        $lines[] = sprintf('Duration: %.2fs', $result->duration);
        $lines[] = '';

        if ($result->parseErrors !== []) {
            $lines[] = 'Parse errors:';
            foreach ($result->parseErrors as $file => $error) {
                $lines[] = sprintf('  %s', $file);
                $lines[] = sprintf('    %s', $error);
            }
            $lines[] = '';
        }

        if ($result->findings !== []) {
            $lines[] = 'Findings:';
            $lines[] = '';

            foreach ($result->findings as $finding) {
                $lines = array_merge($lines, $this->formatFinding($finding));
                $lines[] = '';
            }
        } else {
            $lines[] = 'No findings.';
            $lines[] = '';
        }

        $lines[] = self::RULE;
        $lines[] = $this->summary($result);

        return implode("\n", $lines) . "\n";
    }

    /**
     * @return list<string>
     */
    private function formatFinding(Finding $finding): array
    {
        $lines = [];
        $lines[] = sprintf(
            '%-8s %s %s',
            $finding->severity->value,
            $finding->ruleId,
            $finding->ruleName,
        );
        $lines[] = sprintf('%s:%d', $finding->file, $finding->line);
        $lines[] = $finding->message;

        if ($finding->codeSnippet !== null) {
            $lines[] = sprintf('  > %s', $finding->codeSnippet);
        }

        return $lines;
    }

    private function summary(ScanResult $result): string
    {
        $count = count($result->findings);
        if ($count === 0) {
            return sprintf('%d findings — no security issues detected.', $count);
        }

        $parts = [sprintf('%d finding%s', $count, $count === 1 ? '' : 's')];

        foreach (Severity::cases() as $severity) {
            $key = strtolower($severity->value);
            $countFor = (int) ($result->summary()[$key] ?? 0);
            if ($countFor > 0) {
                $parts[] = sprintf('%d %s', $countFor, $severity->value);
            }
        }

        return implode(PHP_EOL, $parts);
    }
}
