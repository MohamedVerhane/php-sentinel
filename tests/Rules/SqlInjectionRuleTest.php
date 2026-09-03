<?php

declare(strict_types=1);

namespace PhpSentinel\Tests\Rules;

use PhpSentinel\Support\Severity;
use PhpSentinel\Tests\TestCase;

final class SqlInjectionRuleTest extends TestCase
{
    public function testDetectsConcatenatedSqlInjection(): void
    {
        $code = <<<'PHP'
            <?php
            $id = $_GET['id'];
            $query = 'SELECT * FROM users WHERE id = ' . $id;
            $pdo->query($query);
            PHP;

        $finding = $this->assertSingleFinding($this->analyzeWithRule($code, 'SEC001'), 'SEC001');
        self::assertSame(Severity::HIGH, $finding->severity);
        self::assertSame('CWE-89', $finding->cwe);
        self::assertContains('$_GET', $finding->metadata['sources']);
    }

    public function testDetectsInterpolatedSqlInjection(): void
    {
        $code = <<<'PHP'
            <?php
            $id = $_GET['id'];
            $pdo->query("SELECT * FROM users WHERE id = $id");
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testDetectsMysqliQuerySink(): void
    {
        $code = <<<'PHP'
            <?php
            $name = $_POST['name'];
            $sql = 'SELECT * FROM users WHERE name = ' . $name;
            mysqli_query($conn, $sql);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testTracksDataFlowAcrossAssignments(): void
    {
        $code = <<<'PHP'
            <?php
            $id = $_GET['id'];
            $userId = $id;
            $final = trim($userId);
            $mysqli->query('SELECT * FROM users WHERE id = ' . $final);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testIgnoresPreparedStatement(): void
    {
        $code = <<<'PHP'
            <?php
            $id = $_GET['id'];
            $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
            $stmt->execute(['id' => $id]);
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testIgnoresConstantQuery(): void
    {
        $code = <<<'PHP'
            <?php
            $pdo->query('SELECT * FROM users WHERE id = 1');
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testDoesNotFlagExecuteMethodAsSink(): void
    {
        $code = <<<'PHP'
            <?php
            $id = $_GET['id'];
            $stmt->execute([$id]);
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testMetadataIsPresent(): void
    {
        $code = <<<'PHP'
            <?php
            $id = $_GET['id'];
            $pdo->query('SELECT * FROM users WHERE id = ' . $id);
            PHP;

        $finding = $this->assertSingleFinding($this->analyzeWithRule($code, 'SEC001'), 'SEC001');
        self::assertSame('SQL Injection', $finding->ruleName);
        self::assertNotEmpty($finding->description);
        self::assertNotEmpty($finding->recommendation);
    }
}
