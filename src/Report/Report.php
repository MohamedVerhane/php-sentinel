<?php

declare(strict_types=1);

namespace PhpSentinel\Report;

use PhpSentinel\Exception\InvalidInputException;
use PhpSentinel\Scanner\ScanResult;

/**
 * Facade that renders a {@see ScanResult} using a reporter selected by format.
 *
 * Given a format name ('console' or 'json') the report picks the matching
 * reporter. This keeps the CLI decoupled from concrete reporter classes.
 */
final class Report
{
    /**
     * @var array<string, ReporterInterface>
     */
    private array $reporters;

    public function __construct(?ReporterInterface $console = null, ?ReporterInterface $json = null)
    {
        $this->reporters = [
            'console' => $console ?? new ConsoleReporter(),
            'json' => $json ?? new JsonReporter(),
        ];
    }

    /**
     * Returns the supported output format names.
     *
     * @return list<string>
     */
    public function formats(): array
    {
        return array_keys($this->reporters);
    }

    public function supports(string $format): bool
    {
        return isset($this->reporters[$format]);
    }

    public function render(ScanResult $result, string $format = 'console'): string
    {
        if (!isset($this->reporters[$format])) {
            throw new InvalidInputException(sprintf(
                'Unknown output format "%s". Supported formats: %s.',
                $format,
                implode(', ', $this->formats()),
            ));
        }

        return $this->reporters[$format]->render($result);
    }
}
