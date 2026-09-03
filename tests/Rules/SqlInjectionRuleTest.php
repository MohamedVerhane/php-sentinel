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

    public function testDoesNotFlagQueryOnNonDatabaseReceiver(): void
    {
        // Receiver-type awareness: `->query()` on a non-database object (e.g. an
        // HTTP client) is not a SQL sink, so it must not be reported.
        $code = <<<'PHP'
            <?php
            $http = new HttpClient();
            $http->query('SELECT ... ', $_GET['id']);
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testDetectsQueryOnNewPdoInstance(): void
    {
        $code = <<<'PHP'
            <?php
            $pdo = new PDO('sqlite::memory:');
            $pdo->query('SELECT * FROM users WHERE id = ' . $_GET['id']);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testDetectsPgQueryFunctionSink(): void
    {
        $code = <<<'PHP'
            <?php
            $id = $_GET['id'];
            $result = pg_query($conn, 'SELECT * FROM t WHERE id = ' . $id);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testDoesNotFlagQueryOnPlainVariableWithNonDbName(): void
    {
        $code = <<<'PHP'
            <?php
            $client->query('DELETE FROM x WHERE a = ' . $_GET['a']);
            PHP;

        // `$client` is not a recognised DB receiver name, so `->query()` is not
        // treated as a SQL sink even though the argument is tainted.
        self::assertSame([], $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testPreparedStatementInsideMethodNotFlagged(): void
    {
        $code = <<<'PHP'
            <?php
            class Repository {
                public function find($id): void {
                    $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id');
                    $stmt->execute(['id' => $id]);
                }
            }
            (new Repository())->find($_GET['id']);
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC001'));
    }

    public function testMethodBodySinkTaintedByCallArgumentReported(): void
    {
        // The scope-isolation fix must still report a SQL sink inside a method
        // whose parameter is bound from a tainted call site.
        $code = <<<'PHP'
            <?php
            class Dao {
                public function byId($id): void {
                    $this->db->query('SELECT * FROM users WHERE id = ' . $id);
                }
            }
            (new Dao())->byId($_GET['id']);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC001'));
    }
}
