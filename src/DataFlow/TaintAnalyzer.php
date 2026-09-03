<?php

declare(strict_types=1);

namespace PhpSentinel\DataFlow;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\EncapsedStringPart;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Stmt;

/**
 * A lightweight, real inter-procedural-by-approximation taint analyzer.
 *
 * The analyzer walks PHP ASTs, tracks which variables are derived from
 * user-controlled sources (the PHP superglobals), propagates taint through
 * assignments, concatenation, interpolation, casts and function arguments, and
 * honours category-aware sanitizers. It never executes the scanned code.
 *
 * Rules query the analyzer to determine whether an expression that reaches a
 * dangerous sink is tainted without sanitization (see {@see isDangerous()}).
 */
final class TaintAnalyzer
{
    /**
     * The variable names (without the leading `$`) that PHP populates from
     * external input.
     *
     * @var list<string>
     */
    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_FILES'];

    public function __construct(
        private readonly DataFlowContext $context,
    ) {
    }

    public function context(): DataFlowContext
    {
        return $this->context;
    }

    /**
     * Analyzes a list of statements, propagating taint in program order.
     *
     * @param list<Node\Stmt> $statements
     */
    public function analyze(array $statements): void
    {
        $this->propagateStatements($statements);
    }

    /**
     * Returns true when the given expression is derived from user input and has
     * not been neutralised for the given sink category.
     */
    public function isDangerous(Expr $expr, string $category): bool
    {
        $resolved = $this->resolve($expr);

        return $resolved['taintedSources'] !== []
            && !in_array($category, $resolved['sanitizedFor'], true);
    }

    /**
     * Returns the source names (e.g. `$_GET`) that taint the given expression.
     *
     * @return list<string>
     */
    public function sourcesOf(Expr $expr): array
    {
        return $this->resolve($expr)['taintedSources'];
    }

    /**
     * Propagates taint through a list of statements in order.
     *
     * @param list<Node\Stmt> $statements
     */
    private function propagateStatements(array $statements): void
    {
        foreach ($statements as $statement) {
            $this->propagateStatement($statement);
        }
    }

    private function propagateStatement(Node\Stmt $statement): void
    {
        if ($statement instanceof Stmt\Expression) {
            $this->propagateExpr($statement->expr);

            return;
        }

        if ($statement instanceof Stmt\If_) {
            $this->propagateStatements($statement->stmts);
            foreach ($statement->elseifs as $elseIf) {
                $this->propagateStatements($elseIf->stmts);
            }
            if ($statement->else !== null) {
                $this->propagateStatements($statement->else->stmts);
            }

            return;
        }

        if ($statement instanceof Stmt\While_ || $statement instanceof Stmt\Do_) {
            $this->propagateStatements($statement->stmts);

            return;
        }

        if ($statement instanceof Stmt\For_) {
            foreach ($statement->init as $init) {
                $this->propagateExpr($init);
            }
            foreach ($statement->loop as $loop) {
                $this->propagateExpr($loop);
            }
            $this->propagateStatements($statement->stmts);

            return;
        }

        if ($statement instanceof Stmt\Foreach_) {
            $this->propagateExpr($statement->expr);
            if ($statement->keyVar !== null) {
                $this->analyzeTarget($statement->keyVar, $this->resolve($statement->expr));
            }
            if ($statement->valueVar !== null) {
                $this->analyzeTarget($statement->valueVar, $this->resolve($statement->expr));
            }
            $this->propagateStatements($statement->stmts);

            return;
        }

        if ($statement instanceof Stmt\Switch_) {
            foreach ($statement->cases as $case) {
                $this->propagateStatements($case->stmts);
            }

            return;
        }

        if ($statement instanceof Stmt\TryCatch) {
            $this->propagateStatements($statement->stmts);
            foreach ($statement->catches as $catch) {
                $this->propagateStatements($catch->stmts);
            }
            if ($statement->finally !== null) {
                $this->propagateStatements($statement->finally->stmts);
            }

            return;
        }

        if ($statement instanceof Stmt\Function_ || $statement instanceof Stmt\ClassMethod) {
            $this->analyzeFunctionBody(array_values($statement->stmts ?? []));

            return;
        }

        if ($statement instanceof Stmt\Class_ || $statement instanceof Stmt\Interface_ || $statement instanceof Stmt\Trait_) {
            $this->propagateStatements($statement->stmts);

            return;
        }

        if ($statement instanceof Stmt\Namespace_) {
            $this->propagateStatements($statement->stmts);
        }
    }

    /**
     * @param list<Node\Stmt> $statements
     */
    private function analyzeFunctionBody(array $statements): void
    {
        $this->context->reset();
        $this->propagateStatements($statements);
    }

    private function propagateExpr(Node\Expr $expr): void
    {
        if ($expr instanceof Expr\Assign || $expr instanceof Expr\AssignRef) {
            $this->handleAssignment($expr->var, $expr->expr);

            return;
        }

        if ($expr instanceof Expr\AssignOp) {
            [$sources, $sanitized] = $this->mergeEntries(
                $this->resolveTarget($expr->var),
                $this->resolve($expr->expr),
            );
            $this->writeTarget($expr->var, $sources, $sanitized);

            return;
        }

        // Recursively propagate through nested function scopes in expressions.
        if ($expr instanceof Node\Expr\Closure) {
            $this->analyzeFunctionBody(array_values($expr->stmts ?? []));

            return;
        }

        if ($expr instanceof Node\Expr\ArrowFunction && $expr->expr instanceof Node\Expr) {
            $this->propagateExpr($expr->expr);
        }
    }

    private function handleAssignment(Node\Expr $target, Node\Expr $value): void
    {
        $resolved = $this->resolve($value);

        if ($target instanceof Expr\Variable && is_string($target->name)) {
            $this->context->set($target->name, $resolved['taintedSources'], $resolved['sanitizedFor']);

            return;
        }

        $this->analyzeTarget($target, $resolved);
    }

    /**
     * @param array{taintedSources: list<string>, sanitizedFor: list<string>} $resolved
     */
    private function analyzeTarget(Node\Expr $target, array $resolved): void
    {
        $baseName = $this->baseVariableName($target);

        if ($baseName !== null) {
            [$sources, $sanitized] = $this->mergeEntries(
                $this->context->entry($baseName),
                $resolved,
            );
            $this->context->set($baseName, $sources, $sanitized);
        }
    }

    /**
     * Resolves the taint of an expression without side effects.
     *
     * @return array{taintedSources: list<string>, sanitizedFor: list<string>}
     */
    private function resolve(Node\Expr $expr): array
    {
        if ($expr instanceof Expr\Variable) {
            if (is_string($expr->name) && in_array($expr->name, self::SUPERGLOBALS, true)) {
                return ['taintedSources' => ['$' . $expr->name], 'sanitizedFor' => []];
            }

            if (is_string($expr->name)) {
                return $this->context->entry($expr->name);
            }

            return ['taintedSources' => [], 'sanitizedFor' => []];
        }

        if ($expr instanceof Expr\ArrayDimFetch) {
            $base = $this->baseSuperglobal($expr->var);

            if ($base !== null) {
                return ['taintedSources' => ['$' . $base], 'sanitizedFor' => []];
            }

            return $this->resolve($expr->var);
        }

        if ($expr instanceof Expr\BinaryOp\Concat) {
            [$sources, $sanitized] = $this->mergeEntries(
                $this->resolve($expr->left),
                $this->resolve($expr->right),
            );

            return ['taintedSources' => $sources, 'sanitizedFor' => $sanitized];
        }

        if ($expr instanceof Expr\BinaryOp) {
            [$sources, $sanitized] = $this->mergeEntries(
                $this->resolve($expr->left),
                $this->resolve($expr->right),
            );

            return ['taintedSources' => $sources, 'sanitizedFor' => $sanitized];
        }

        if ($expr instanceof Expr\FuncCall) {
            return $this->resolveFunctionCall($expr);
        }

        if ($expr instanceof Expr\MethodCall) {
            $sources = $this->collectArgumentSources($expr->args);

            return ['taintedSources' => $sources, 'sanitizedFor' => []];
        }

        if ($expr instanceof Expr\StaticCall) {
            $sources = $this->collectArgumentSources($expr->args);

            return ['taintedSources' => $sources, 'sanitizedFor' => []];
        }

        if ($expr instanceof InterpolatedString) {
            $sources = [];
            foreach ($expr->parts as $part) {
                if ($part instanceof EncapsedStringPart) {
                    continue;
                }

                if ($part instanceof Node\Expr) {
                    $sources = array_merge($sources, $this->resolve($part)['taintedSources']);
                }
            }

            $sources = array_values(array_unique($sources));

            return ['taintedSources' => $sources, 'sanitizedFor' => []];
        }

        if ($expr instanceof Expr\ShellExec) {
            $sources = [];
            foreach ($expr->parts as $part) {
                if ($part instanceof EncapsedStringPart) {
                    continue;
                }
                if ($part instanceof Node\Expr) {
                    $sources = array_merge($sources, $this->resolve($part)['taintedSources']);
                }
            }

            return ['taintedSources' => array_values(array_unique($sources)), 'sanitizedFor' => []];
        }

        if ($expr instanceof Expr\Ternary) {
            [$sources, $sanitized] = $this->mergeEntries(
                $this->resolve($expr->cond),
                $this->resolve($expr->else),
            );
            if ($expr->if !== null) {
                [$sources, $sanitized] = $this->mergeEntries(
                    ['taintedSources' => $sources, 'sanitizedFor' => $sanitized],
                    $this->resolve($expr->if),
                );
            }

            return ['taintedSources' => $sources, 'sanitizedFor' => $sanitized];
        }

        if ($expr instanceof Expr\Cast) {
            return $this->resolve($expr->expr);
        }

        if ($expr instanceof Expr\Array_) {
            $sources = [];
            foreach ($expr->items as $item) {
                if ($item === null) {
                    continue;
                }
                $sources = array_merge($sources, $item->value instanceof Expr ? $this->resolve($item->value)['taintedSources'] : []);
            }

            return ['taintedSources' => array_values(array_unique($sources)), 'sanitizedFor' => []];
        }

        if (
            $expr instanceof Expr\PropertyFetch
            || $expr instanceof Expr\NullsafePropertyFetch
        ) {
            return $this->resolve($expr->var);
        }

        // String literals, numbers, constants, class constants and everything
        // else are treated as clean unless explicitly propagated.
        return ['taintedSources' => [], 'sanitizedFor' => []];
    }

    /**
     * @return array{taintedSources: list<string>, sanitizedFor: list<string>}
     */
    private function resolveFunctionCall(Expr\FuncCall $call): array
    {
        $argumentSources = $this->collectArgumentSources($call->args);

        if ($call->name instanceof Name) {
            $name = $this->functionName($call->name);
            $categories = $this->context->sanitizerCategoriesFor($name);
            if ($categories !== []) {
                return ['taintedSources' => $argumentSources, 'sanitizedFor' => $categories];
            }
        }

        return ['taintedSources' => $argumentSources, 'sanitizedFor' => []];
    }

    /**
     * Collects the tainted sources from a list of call arguments.
     *
     * @param list<Node\Arg|Node\VariadicPlaceholder> $args
     *
     * @return list<string>
     */
    private function collectArgumentSources(array $args): array
    {
        $sources = [];
        foreach ($args as $arg) {
            if (!$arg instanceof Node\Arg || !$arg->value instanceof Expr) {
                continue;
            }
            $sources = array_merge($sources, $this->resolve($arg->value)['taintedSources']);
        }

        return array_values(array_unique($sources));
    }

    /**
     * @param array{taintedSources: list<string>, sanitizedFor: list<string>} $left
     * @param array{taintedSources: list<string>, sanitizedFor: list<string>} $right
     *
     * @return array{0: list<string>, 1: list<string>}
     */
    private function mergeEntries(array $left, array $right): array
    {
        $sources = array_values(array_unique(array_merge($left['taintedSources'], $right['taintedSources'])));
        $categories = array_values(array_unique(array_merge($left['sanitizedFor'], $right['sanitizedFor'])));

        // A value is safe for a category only when both contributing operands
        // are safe for that category.
        $categories = array_values(array_filter(
            $categories,
            static function (string $category) use ($left, $right): bool {
                $leftSafe = $left['taintedSources'] === [] || in_array($category, $left['sanitizedFor'], true);
                $rightSafe = $right['taintedSources'] === [] || in_array($category, $right['sanitizedFor'], true);

                return $leftSafe && $rightSafe;
            },
        ));

        return [$sources, $categories];
    }

    /**
     * Determines the target variable entry (via {@see resolveTarget}) and writes
     * it back using the base variable name when possible.
     *
     * @param list<string> $sources
     * @param list<string> $sanitized
     */
    private function writeTarget(Node\Expr $target, array $sources, array $sanitized): void
    {
        $baseName = $this->baseVariableName($target);
        if ($baseName !== null) {
            $this->context->set($baseName, $sources, $sanitized);
        }
    }

    /**
     * @return array{taintedSources: list<string>, sanitizedFor: list<string>}
     */
    private function resolveTarget(Node\Expr $target): array
    {
        $baseName = $this->baseVariableName($target);

        return $baseName !== null ? $this->context->entry($baseName) : $this->resolve($target);
    }

    /**
     * Returns the base variable name of a simple variable or an array element
     * target, or null when the target is not a plain variable.
     */
    private function baseVariableName(Node\Expr $target): ?string
    {
        if ($target instanceof Expr\Variable && is_string($target->name)) {
            return $target->name;
        }

        if ($target instanceof Expr\ArrayDimFetch) {
            return $this->baseVariableName($target->var);
        }

        return null;
    }

    /**
     * Returns the base name of the superglobal variable, or null when the given
     * expression is not a superglobal variable.
     */
    private function baseSuperglobal(Node\Expr $expr): ?string
    {
        if (!$expr instanceof Expr\Variable || !is_string($expr->name)) {
            return null;
        }

        return in_array($expr->name, self::SUPERGLOBALS, true) ? $expr->name : null;
    }

    /**
     * Returns the lower-cased function name (last segment).
     */
    private function functionName(Identifier|Name $name): string
    {
        if ($name instanceof Name) {
            $segments = $name->getParts();

            return strtolower(end($segments) ?: '');
        }

        return strtolower($name->toString());
    }
}
