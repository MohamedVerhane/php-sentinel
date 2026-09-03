<?php

declare(strict_types=1);

namespace PhpSentinel\Tests\Rules;

use PhpSentinel\Support\Severity;
use PhpSentinel\Tests\TestCase;

final class FileInclusionRuleTest extends TestCase
{
    public function testDetectsIncludeOfUserInput(): void
    {
        $code = <<<'PHP'
            <?php
            $file = $_GET['page'];
            include $file;
            PHP;

        $finding = $this->assertSingleFinding($this->analyzeWithRule($code, 'SEC004'), 'SEC004');
        self::assertSame(Severity::HIGH, $finding->severity);
        self::assertSame('CWE-98', $finding->cwe);
        self::assertContains('$_GET', $finding->metadata['sources']);
    }

    public function testDetectsRequireOnceSink(): void
    {
        $code = <<<'PHP'
            <?php
            require_once $_POST['view'];
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC004'));
    }

    public function testDetectsConcatenatedInclude(): void
    {
        $code = <<<'PHP'
            <?php
            $lang = $_COOKIE['lang'];
            include 'templates/' . $lang . '.php';
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC004'));
    }

    public function testIgnoresStaticInclude(): void
    {
        $code = <<<'PHP'
            <?php
            include 'config.php';
            require_once 'vendor/autoload.php';
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC004'));
    }
}
