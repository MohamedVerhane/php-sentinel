<?php

declare(strict_types=1);

namespace PhpSentinel\Tests\Rules;

use PhpSentinel\Support\Severity;
use PhpSentinel\Tests\TestCase;

final class XssRuleTest extends TestCase
{
    public function testDetectsEchoOfUserInput(): void
    {
        $code = <<<'PHP'
            <?php
            $name = $_GET['name'];
            echo $name;
            PHP;

        $finding = $this->assertSingleFinding($this->analyzeWithRule($code, 'SEC002'), 'SEC002');
        self::assertSame(Severity::MEDIUM, $finding->severity);
        self::assertSame('CWE-79', $finding->cwe);
        self::assertContains('$_GET', $finding->metadata['sources']);
    }

    public function testDetectsPrintOfUserInput(): void
    {
        $code = <<<'PHP'
            <?php
            print $_POST['message'];
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testDetectsConcatFlowingToEcho(): void
    {
        $code = <<<'PHP'
            <?php
            $user = $_GET['user'];
            $template = 'Hi ' . $user;
            echo $template;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testDetectsPrintfArgument(): void
    {
        $code = <<<'PHP'
            <?php
            $body = $_POST['body'];
            printf('Message: %s', $body);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testIgnoresEscapedOutput(): void
    {
        $code = <<<'PHP'
            <?php
            $name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
            echo $name;
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testIgnoresStaticOutput(): void
    {
        $code = <<<'PHP'
            <?php
            echo 'Static text';
            print 'More static';
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testSanitizerDoesNotSilenceOtherTraces(): void
    {
        // Only the escaped value is echoed; the raw value is still dangerous.
        $code = <<<'PHP'
            <?php
            $raw = $_GET['x'];
            $escaped = htmlspecialchars($raw, ENT_QUOTES, 'UTF-8');
            echo $escaped;
            echo $raw;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }
}
