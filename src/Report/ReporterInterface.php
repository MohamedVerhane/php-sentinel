<?php

declare(strict_types=1);

namespace PhpSentinel\Report;

use PhpSentinel\Scanner\ScanResult;

/**
 * Renders a {@see ScanResult} into a plain string that the CLI can write out.
 *
 * Reporters are pure: they never write to a stream themselves, which keeps them
 * easy to unit test and lets the CLI decide where output goes. JSON reporters
 * must produce exactly one valid JSON document and no stray console text.
 */
interface ReporterInterface
{
    public function render(ScanResult $result): string;
}
