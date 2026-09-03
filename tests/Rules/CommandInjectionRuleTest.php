<?php

declare(strict_types=1);

namespace PhpSentinel\Tests\Rules;

use PhpSentinel\Support\Severity;
use PhpSentinel\Tests\TestCase;

final class CommandInjectionRuleTest extends TestCase
{
    public function testDetectsSystemSink(): void
    {
        $code = <<<'PHP'
            <?php
            $cmd = $_GET['cmd'];
            system($cmd);
            PHP;

        $finding = $this->assertSingleFinding($this->analyzeWithRule($code, 'SEC003'), 'SEC003');
        self::assertSame(Severity::HIGH, $finding->severity);
        self::assertSame('CWE-78', $finding->cwe);
        self::assertContains('$_GET', $finding->metadata['sources']);
    }

    public function testDetectsExecSink(): void
    {
        $code = <<<'PHP'
            <?php
            exec($_POST['cmd']);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC003'));
    }

    public function testDetectsShellExeCSink(): void
    {
        $code = <<<'PHP'
            <?php
            $dir = $_GET['dir'];
            shell_exec('ls ' . $dir);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC003'));
    }

    public function testDetectsBacktickInterpolation(): void
    {
        $code = <<<'PHP'
            <?php
            $host = $_GET['host'];
            `ping $host`;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC003'));
    }

    public function testIgnoresConstantCommand(): void
    {
        $code = <<<'PHP'
            <?php
            system('ls -la');
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC003'));
    }

    public function testIgnoresEscapedCommand(): void
    {
        $code = <<<'PHP'
            <?php
            $arg = escapeshellarg($_GET['arg']);
            system('echo ' . $arg);
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC003'));
    }
}
