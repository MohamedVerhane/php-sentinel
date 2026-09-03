<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpSentinel\Support\Finding;
use PhpSentinel\Support\Severity;

/**
 * Detects command injection: user-controlled data reaching command execution
 * functions without being neutralised.
 *
 * The rule recognises the common PHP shell-execution sinks and uses the taint
 * analyzer to determine whether the command argument derives from user input.
 * Calls where the command is a constant or is otherwise not user controlled are
 * deliberately not flagged.
 *
 * @note Passing user input to a shell is dangerous even when escaped; the most
 *       reliable defence is to avoid invoking a shell altogether.
 */
final class CommandInjectionRule extends AbstractRule
{
    public const ID = 'SEC003';

    /**
     * Command execution functions mapped to the index of the command argument.
     *
     * @var array<string, int>
     */
    private const FUNCTION_SINKS = [
        'system' => 0,
        'exec' => 0,
        'shell_exec' => 0,
        'passthru' => 0,
        'proc_open' => 0,
        'popen' => 0,
    ];

    private const SINK_CATEGORY = 'command';

    public function id(): string
    {
        return self::ID;
    }

    public function name(): string
    {
        return 'Command Injection';
    }

    public function description(): string
    {
        return 'User-controlled input is passed to a shell command, allowing an attacker to execute arbitrary '
            . 'commands on the server if the input is not validated or escaped.';
    }

    public function severity(): Severity
    {
        return Severity::HIGH;
    }

    public function cwe(): ?string
    {
        return 'CWE-78';
    }

    public function remediation(): string
    {
        return 'Avoid invoking the shell entirely — prefer high-level library APIs that do not execute commands. '
            . 'If a shell is unavoidable, pass arguments via arrays (e.g. proc_open or shell_exec with escaped '
            . 'arguments using escapeshellarg) or use a strict allow-list and never interpolate raw input.';
    }

    public function analyze(Node $node, RuleContext $context): array
    {
        if ($node instanceof Expr\ShellExec) {
            if (!$context->analyzer->isDangerous($node, self::SINK_CATEGORY)) {
                return [];
            }

            $sources = $context->analyzer->sourcesOf($node);
            $sourceList = $sources === [] ? 'User-controlled' : 'User-controlled input (' . implode(', ', $sources) . ')';

            return [
                $this->makeFinding(
                    'Potential Command Injection',
                    sprintf(
                        '%s reaches the shell command via backtick execution without being escaped. Avoid shell '
                        . 'execution where possible.',
                        $sourceList,
                    ),
                    $context,
                    $node,
                    ['sinks' => ['command-injection'], 'sources' => $sources],
                ),
            ];
        }

        if (!$node instanceof Expr\FuncCall) {
            return [];
        }

        if (!$node->name instanceof Node\Name) {
            return [];
        }

        $name = $this->functionName($node->name);
        if (!isset(self::FUNCTION_SINKS[$name])) {
            return [];
        }

        $commandIndex = self::FUNCTION_SINKS[$name];
        $args = $node->getArgs();
        if (!isset($args[$commandIndex]) || !$args[$commandIndex]->value instanceof Expr) {
            return [];
        }

        $command = $args[$commandIndex]->value;
        if (!$context->analyzer->isDangerous($command, self::SINK_CATEGORY)) {
            return [];
        }

        $sources = $context->analyzer->sourcesOf($command);
        $sourceList = $sources === [] ? 'User-controlled' : 'User-controlled input (' . implode(', ', $sources) . ')';

        return [
            $this->makeFinding(
                'Potential Command Injection',
                sprintf(
                    '%s reaches the shell command %s() without being escaped. Avoid shell execution where possible.',
                    $sourceList,
                    $name,
                ),
                $context,
                $node,
                ['sinks' => ['command-injection'], 'sources' => $sources],
            ),
        ];
    }

    private function functionName(Node\Name|Node\Identifier $name): string
    {
        if ($name instanceof Node\Name) {
            $parts = $name->getParts();

            return strtolower(end($parts) ?: '');
        }

        return strtolower($name->toString());
    }
}
