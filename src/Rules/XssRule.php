<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpSentinel\Support\Finding;
use PhpSentinel\Support\Severity;

/**
 * Detects reflected / stored cross-site scripting (XSS): user-controlled data
 * reaching HTML output sinks without being HTML-escaped.
 *
 * The rule inspects `echo`, `print` and `printf` outputs and uses the taint
 * analyzer to determine whether the output is derived from user input and has
 * not been escaped with a recognised HTML sanitizer (`htmlspecialchars` or
 * `htmlentities`).
 *
 * @note Static analysis cannot model every escaping context (attribute vs.
 *       text vs. JavaScript, nested HTML, double encoding, etc.). A negative
 *       result does not guarantee the output is safe, and a positive result may
 *       occasionally be a false positive when escaping is performed indirectly.
 */
final class XssRule extends AbstractRule
{
    public const ID = 'SEC002';

    private const SINK_CATEGORY = 'xss';

    public function id(): string
    {
        return self::ID;
    }

    public function name(): string
    {
        return 'Cross-Site Scripting (XSS)';
    }

    public function description(): string
    {
        return 'User-controlled data is emitted into an HTML response without being escaped, allowing an attacker '
            . 'to inject script that executes in the context of the victim\'s browser.';
    }

    public function severity(): Severity
    {
        return Severity::MEDIUM;
    }

    public function cwe(): ?string
    {
        return 'CWE-79';
    }

    public function remediation(): string
    {
        return 'Encode all dynamic output with context-appropriate escaping. For HTML use htmlspecialchars($value, '
            . 'ENT_QUOTES, "UTF-8"). Consider using a templating engine that escapes by default, and apply a '
            . 'Content-Security-Policy to limit the impact of injection.';
    }

    public function analyze(Node $node, RuleContext $context): array
    {
        if ($node instanceof Stmt\Echo_) {
            $findings = [];
            foreach ($node->exprs as $expr) {
                if ($this->isDangerousOutput($expr, $context)) {
                    $findings[] = $this->finding('Potential Cross-Site Scripting (XSS)', $expr, $context, $expr);
                }
            }

            return $findings;
        }

        if ($node instanceof Expr\Print_) {
            if ($this->isDangerousOutput($node->expr, $context)) {
                return [$this->finding('Potential Cross-Site Scripting (XSS)', $node, $context, $node->expr)];
            }

            return [];
        }

        if ($node instanceof Expr\FuncCall) {
            if (!$node->name instanceof Node\Name) {
                return [];
            }

            $name = $this->functionName($node->name);
            if ($name === 'printf' || $name === 'vprintf') {
                // Only printf/vprintf emit output directly. sprintf returns a
                // string, so its taint is tracked by the taint analyzer and
                // reported once at the surrounding echo/print sink.
                $findings = [];
                foreach ($node->getArgs() as $arg) {
                    if (!$arg->value instanceof Expr) {
                        continue;
                    }
                    if ($this->isDangerousOutput($arg->value, $context)) {
                        $findings[] = $this->finding('Potential Cross-Site Scripting (XSS)', $arg->value, $context, $arg->value);
                    }
                }

                return $findings;
            }
        }

        return [];
    }

    private function isDangerousOutput(Expr $expr, RuleContext $context): bool
    {
        return $context->analyzer->isDangerous($expr, self::SINK_CATEGORY);
    }

    private function finding(string $title, Node $at, RuleContext $context, Expr $sourceExpr): Finding
    {
        $sources = $context->analyzer->sourcesOf($sourceExpr);
        $sourceList = $sources === [] ? 'User-controlled' : 'User-controlled input (' . implode(', ', $sources) . ')';

        return $this->makeFinding(
            $title,
            sprintf('%s reaches HTML output without being escaped. Escape it with htmlspecialchars().', $sourceList),
            $context,
            $at,
            ['sinks' => ['xss'], 'sources' => $sources],
        );
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
