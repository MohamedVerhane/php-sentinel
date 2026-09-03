<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpSentinel\Support\Finding;
use PhpSentinel\Support\Severity;

/**
 * Detects SQL injection: user-controlled data reaching SQL execution sinks
 * without being neutralised.
 *
 * The rule identifies calls to common SQL execution functions and methods and
 * uses the taint analyzer to determine whether the SQL argument derives from
 * user input. Prepared statements (e.g. `PDO::prepare` + `execute`) are not
 * treated as sinks and are therefore never flagged.
 *
 * @note Static analysis cannot prove the absence of SQL injection. The lack of
 *       a finding does not guarantee the code is safe.
 */
final class SqlInjectionRule extends AbstractRule
{
    public const ID = 'SEC001';

    /**
     * SQL execution functions mapped to the index of the SQL argument.
     *
     * @var array<string, int>
     */
    private const FUNCTION_SINKS = [
        'mysqli_query' => 1,
        'mysqli_multi_query' => 1,
    ];

    /**
     * SQL execution method names. These methods take the SQL as their first
     * argument.
     *
     * @var list<string>
     */
    private const METHOD_SINKS = ['query', 'exec', 'multi_query'];

    private const SINK_CATEGORY = 'sql';

    public function id(): string
    {
        return self::ID;
    }

    public function name(): string
    {
        return 'SQL Injection';
    }

    public function description(): string
    {
        return 'User-controlled input is concatenated or interpolated into a SQL query without being parameterised, '
            . 'which can allow an attacker to alter the query and read or modify data they should not be able to access.';
    }

    public function severity(): Severity
    {
        return Severity::HIGH;
    }

    public function cwe(): ?string
    {
        return 'CWE-89';
    }

    public function remediation(): string
    {
        return 'Use parameterised queries / prepared statements (e.g. PDO::prepare with bound parameters or '
            . 'mysqli prepared statements). Never concatenate or interpolate user input directly into SQL, and '
            . 'always apply strict allow-list validation when a dynamic identifier or keyword must be used.';
    }

    public function analyze(Node $node, RuleContext $context): array
    {
        if ($node instanceof Expr\FuncCall) {
            if (!$node->name instanceof Node\Name) {
                return [];
            }

            $name = $this->functionName($node->name);
            if (isset(self::FUNCTION_SINKS[$name])) {
                return $this->checkSink($node, self::FUNCTION_SINKS[$name], $context, $node);
            }

            return [];
        }

        if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            if (!$node->name instanceof Node\Identifier) {
                return [];
            }

            $method = strtolower($node->name->toString());
            if (in_array($method, self::METHOD_SINKS, true)) {
                return $this->checkSink($node, 0, $context, $node);
            }
        }

        return [];
    }

    /**
     * @return list<Finding>
     */
    private function checkSink(Expr\CallLike $node, int $sqlArgumentIndex, RuleContext $context, Node $at): array
    {
        $args = $this->args($node);
        if (!isset($args[$sqlArgumentIndex])) {
            return [];
        }

        $sql = $args[$sqlArgumentIndex]->value;
        if (!$sql instanceof Expr) {
            return [];
        }

        if (!$context->analyzer->isDangerous($sql, self::SINK_CATEGORY)) {
            return [];
        }

        $sources = $context->analyzer->sourcesOf($sql);
        $sourceList = $sources === [] ? 'user input' : implode(', ', $sources);

        return [
            $this->makeFinding(
                'Potential SQL Injection',
                sprintf(
                    'User-controlled input (%s) reaches a SQL query. Use a prepared statement with bound parameters.',
                    $sourceList,
                ),
                $context,
                $at,
                ['sinks' => ['sql-injection'], 'sources' => $sources],
            ),
        ];
    }

    /**
     * Returns the callable's argument list as a flat array.
     *
     * @return list<Node\Arg>
     */
    private function args(Expr\CallLike $call): array
    {
        $args = [];
        foreach ($call->getArgs() as $arg) {
            if ($arg instanceof Node\Arg) {
                $args[] = $arg;
            }
        }

        return $args;
    }

    /**
     * Returns the lower-cased function name from a callable name node.
     */
    private function functionName(Node\Name|Node\Identifier $name): string
    {
        if ($name instanceof Node\Name) {
            $parts = $name->getParts();

            return strtolower(end($parts) ?: '');
        }

        return strtolower($name->toString());
    }
}
