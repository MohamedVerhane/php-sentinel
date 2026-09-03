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
use PhpParser\NodeFinder;

/**
 * A lightweight, real inter-procedural-by-approximation taint analyzer.
 *
 * The analyzer walks PHP ASTs, tracks which variables are derived from
 * user-controlled sources (the PHP superglobals), propagates taint through
 * assignments, concatenation, interpolation, casts and function arguments, and
 * honours category-aware sanitizers. It never executes the scanned code.
 *
 * Scopes are modelled pragmatically: function, method and closure bodies are
 * analysed in an isolated child scope that is discarded afterwards, so a
 * function body never clobbers the surrounding scope and locals never leak
 * between functions. Branching statements (if/switch/try) merge their paths
 * using a must-taint rule: a value is only considered tainted after a branch
 * structure when it is tainted identically on every path. User-defined
 * functions and methods contribute their return taint (and tainted parameters)
 * to the call sites that pass them tainted arguments.
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

    /**
     * User-defined functions and methods indexed by lower-cased name.
     *
     * @var array<string, array{params: list<string>, stmts: list<Node\Stmt>}>
     */
    private array $functions = [];

    /**
     * Names of functions currently being resolved, to guard against recursion.
     *
     * @var array<string, true>
     */
    private array $resolving = [];

    /**
     * Index of every function-like scope, used to resolve an expression's
     * lexical scope after the analysis pass.
     *
     * @var list<array{key: int, start: int, end: int}>
     */
    private array $scopeIndex = [];

    /**
     * Per-scope variable states captured when each function/method/closure body
     * finished analysing. Keyed by {@see spl_object_id()} of the scope node.
     *
     * @var array<int, array<string, array{taintedSources: list<string>, sanitizedFor: list<string>}>>
     */
    private array $scopeStates = [];

    /**
     * Maps a lower-cased function/method name to the scope keys that declare it.
     *
     * @var array<string, list<int>>
     */
    private array $scopeKeysByName = [];

    /**
     * The final variable state of the top-level (global) scope, captured after
     * the analysis pass. Used to resolve expressions not inside any function.
     *
     * @var array<string, array{taintedSources: list<string>, sanitizedFor: list<string>}>
     */
    private array $globalState = [];

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
        $this->buildIndex($statements);
        $this->buildScopeIndex($statements);
        $this->propagateStatements($statements);
        $this->bindTaintedMethodParameters($statements);
        $this->globalState = $this->context->snapshot();
    }

    /**
     * Returns true when the given expression is derived from user input and has
     * not been neutralised for the given sink category.
     */
    public function isDangerous(Expr $expr, string $category): bool
    {
        $resolved = $this->resolveInScope($expr);

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
        return $this->resolveInScope($expr)['taintedSources'];
    }

    /**
     * Indexes every function-like scope (function, method, closure) so that an
     * expression can later be resolved against its own lexical scope rather
     * than a single shared context.
     *
     * @param list<Node\Stmt> $statements
     */
    private function buildScopeIndex(array $statements): void
    {
        if ($statements === []) {
            return;
        }

        $nodes = (new NodeFinder())->find($statements, static fn (Node $node): bool => true);

        foreach ($nodes as $node) {
            if (
                $node instanceof Stmt\Function_
                || $node instanceof Stmt\ClassMethod
                || $node instanceof Expr\Closure
                || $node instanceof Expr\ArrowFunction
            ) {
                $key = spl_object_id($node);
                $this->scopeIndex[] = [
                    'key' => $key,
                    'start' => $node->getStartLine(),
                    'end' => $node->getEndLine(),
                ];

                if ($node instanceof Stmt\Function_ || $node instanceof Stmt\ClassMethod) {
                    $name = strtolower($node->name->toString());
                    $this->scopeKeysByName[$name][] = $key;
                }
            }
        }
    }

    /**
     * Indexes the user-defined functions and methods declared in the AST so
     * that their parameters and return statements can be resolved at call
     * sites.
     *
     * @param list<Node\Stmt> $statements
     */
    private function buildIndex(array $statements): void
    {
        if ($statements === []) {
            return;
        }

        $nodes = (new NodeFinder())->find($statements, static fn (Node $node): bool => true);

        foreach ($nodes as $node) {
            if ($node instanceof Stmt\Function_) {
                $name = strtolower($node->name->toString());
                $this->functions[$name] = [
                    'params' => $this->parameterNames($node->params),
                    'stmts' => array_values($node->stmts ?? []),
                ];
            } elseif ($node instanceof Stmt\ClassMethod) {
                $name = strtolower($node->name->toString());
                $this->functions[$name] = [
                    'params' => $this->parameterNames($node->params),
                    'stmts' => array_values($node->stmts ?? []),
                ];
            }
        }
    }

    /**
     * Returns the lower-cased names of a parameter list.
     *
     * @param list<Node\Param> $params
     *
     * @return list<string>
     */
    private function parameterNames(array $params): array
    {
        $names = [];
        foreach ($params as $param) {
            if ($param->var instanceof Expr\Variable && is_string($param->var->name)) {
                $names[] = $param->var->name;
            }
        }

        return $names;
    }

    /**
     * After the main pass, binds taint to the parameters of user-defined
     * methods that are invoked with tainted arguments. This lets sinks inside a
     * method body (e.g. an `echo $param` inside a method called with `$_GET`)
     * be reported even though the method body is analysed in an isolated scope.
     *
     * @param list<Node\Stmt> $statements
     */
    private function bindTaintedMethodParameters(array $statements): void
    {
        if ($statements === [] || $this->functions === []) {
            return;
        }

        $taintedCalls = $this->findTaintedMethodCalls($statements);

        foreach ($taintedCalls as $name => $sources) {
            $params = $this->functions[$name]['params'] ?? [];
            if ($params === [] || !isset($this->scopeKeysByName[$name])) {
                continue;
            }

            // Bind the tainted arguments into the *declaring method's* scope
            // state only, so that a top-level variable sharing a parameter name
            // is never polluted by the binding.
            foreach ($this->scopeKeysByName[$name] as $scopeKey) {
                if (!isset($this->scopeStates[$scopeKey])) {
                    continue;
                }

                $state = $this->scopeStates[$scopeKey];
                foreach ($params as $param) {
                    [$existingSources, $existingSanitized] = $this->mergeEntries(
                        $state[$param] ?? ['taintedSources' => [], 'sanitizedFor' => []],
                        ['taintedSources' => $sources, 'sanitizedFor' => []],
                    );
                    $state[$param] = ['taintedSources' => $existingSources, 'sanitizedFor' => $existingSanitized];
                }
                $this->scopeStates[$scopeKey] = $state;
            }
        }
    }

    /**
     * Collects the method names invoked with at least one tainted argument
     * anywhere in the AST.
     *
     * @param list<Node\Stmt> $statements
     *
     * @return array<string, list<string>> method name => merged source names
     */
    private function findTaintedMethodCalls(array $statements): array
    {
        $calls = [];
        $nodes = (new NodeFinder())->find(
            $statements,
            static fn (Node $node): bool => $node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall,
        );

        foreach ($nodes as $node) {
            $name = $this->methodCallName($node);
            if ($name === null || !isset($this->functions[$name])) {
                continue;
            }
            if (!$node instanceof Expr\MethodCall && !$node instanceof Expr\StaticCall) {
                continue;
            }
            $sources = $this->collectArgumentSources($node->args);
            $sources = array_values(array_unique($sources));
            if ($sources === []) {
                continue;
            }
            $calls[$name] = array_values(array_unique(array_merge($calls[$name] ?? [], $sources)));
        }

        return $calls;
    }

    private function methodCallName(Node $node): ?string
    {
        if ($node instanceof Expr\MethodCall) {
            $name = $node->name;
        } elseif ($node instanceof Expr\StaticCall) {
            $name = $node->name;
        } else {
            return null;
        }

        if ($name instanceof Identifier) {
            return strtolower($name->toString());
        }

        return null;
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
            $before = $this->context->snapshot();
            $paths = [];

            $this->context->restore($before);
            $this->propagateStatements($statement->stmts);
            $paths[] = $this->context->snapshot();

            foreach ($statement->elseifs as $elseIf) {
                $this->context->restore($before);
                $this->propagateStatements($elseIf->stmts);
                $paths[] = $this->context->snapshot();
            }

            if ($statement->else !== null) {
                $this->context->restore($before);
                $this->propagateStatements($statement->else->stmts);
                $paths[] = $this->context->snapshot();
            } else {
                $paths[] = $before;
            }

            $this->context->restore(DataFlowContext::mergeStates($paths));

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
            $before = $this->context->snapshot();
            $paths = [];
            $hasDefault = false;

            foreach ($statement->cases as $case) {
                $this->context->restore($before);
                $this->propagateStatements($case->stmts);
                $paths[] = $this->context->snapshot();
                if ($case->cond === null) {
                    $hasDefault = true;
                }
            }

            if (!$hasDefault) {
                $paths[] = $before;
            }

            $this->context->restore(DataFlowContext::mergeStates($paths));

            return;
        }

        if ($statement instanceof Stmt\TryCatch) {
            $before = $this->context->snapshot();
            $paths = [];

            $this->context->restore($before);
            $this->propagateStatements($statement->stmts);
            $paths[] = $this->context->snapshot();

            foreach ($statement->catches as $catch) {
                $this->context->restore($before);
                $this->propagateStatements($catch->stmts);
                $paths[] = $this->context->snapshot();
            }

            if ($statement->finally !== null) {
                $this->context->restore($before);
                $this->propagateStatements($statement->finally->stmts);
                $paths[] = $this->context->snapshot();
            }

            $this->context->restore(DataFlowContext::mergeStates($paths));

            return;
        }

        if ($statement instanceof Stmt\Function_ || $statement instanceof Stmt\ClassMethod) {
            $this->analyzeFunctionBody($statement, array_values($statement->stmts ?? []));

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
    private function analyzeFunctionBody(Node $scopeNode, array $statements): void
    {
        $snapshot = $this->context->snapshot();
        $this->context->reset();
        $this->propagateStatements($statements);
        $this->scopeStates[spl_object_id($scopeNode)] = $this->context->snapshot();
        $this->context->restore($snapshot);
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
            $this->analyzeFunctionBody($expr, array_values($expr->stmts ?? []));

            return;
        }

        if ($expr instanceof Node\Expr\ArrowFunction && $expr->expr instanceof Node\Expr) {
            $snapshot = $this->context->snapshot();
            $this->context->reset();
            $this->propagateExpr($expr->expr);
            $this->scopeStates[spl_object_id($expr)] = $this->context->snapshot();
            $this->context->restore($snapshot);

            return;
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
     * Resolves taint for a node that lives inside the AST, loading the variable
     * state of the node's own lexical scope so that findings always use the
     * correct scope and state never leaks between functions/methods. Falls back
     * to the top-level state for nodes not inside any function-like scope.
     *
     * @return array{taintedSources: list<string>, sanitizedFor: list<string>}
     */
    private function resolveInScope(Expr $expr): array
    {
        $key = $this->scopeKeyForLine($expr->getStartLine());
        $state = $key === null ? $this->globalState : ($this->scopeStates[$key] ?? []);

        $snapshot = $this->context->snapshot();
        $this->context->restore($state);

        try {
            return $this->resolve($expr);
        } finally {
            $this->context->restore($snapshot);
        }
    }

    /**
     * Returns the scope key of the innermost function-like scope whose line
     * range contains `$line`, or null when the line is not inside any function.
     */
    private function scopeKeyForLine(int $line): ?int
    {
        $best = null;
        $bestSize = null;

        foreach ($this->scopeIndex as $scope) {
            if ($line < $scope['start'] || $line > $scope['end']) {
                continue;
            }

            $size = $scope['end'] - $scope['start'];
            if ($bestSize === null || $size < $bestSize) {
                $bestSize = $size;
                $best = $scope['key'];
            }
        }

        return $best;
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

            if (isset($this->functions[$name])) {
                return $this->resolveUserFunctionReturn($name, $argumentSources);
            }
        }

        return ['taintedSources' => $argumentSources, 'sanitizedFor' => []];
    }

    /**
     * Resolves the taint contributed by a user-defined function's return
     * statement(s) for the given call site, binding the call args to the
     * function parameters.
     *
     * @param list<string> $callSources
     *
     * @return array{taintedSources: list<string>, sanitizedFor: list<string>}
     */
    private function resolveUserFunctionReturn(string $name, array $callSources): array
    {
        $definition = $this->functions[$name];
        if (isset($this->resolving[$name])) {
            return ['taintedSources' => $callSources, 'sanitizedFor' => []];
        }

        $this->resolving[$name] = true;
        $snapshot = $this->context->snapshot();
        $this->context->reset();

        foreach ($definition['params'] as $param) {
            $this->context->set($param, $callSources, []);
        }

        $this->propagateStatements($definition['stmts']);
        $return = $this->collectReturnTaint($definition['stmts']);

        $this->context->restore($snapshot);
        unset($this->resolving[$name]);

        return $return;
    }

    /**
     * Merges the taint of all top-level `return` statements in a function body.
     *
     * @param list<Node\Stmt> $statements
     *
     * @return array{taintedSources: list<string>, sanitizedFor: list<string>}
     */
    private function collectReturnTaint(array $statements): array
    {
        $sources = [];
        $sanitized = [];
        $found = false;

        foreach ($statements as $statement) {
            if ($statement instanceof Stmt\Return_) {
                if ($statement->expr instanceof Expr) {
                    $resolved = $this->resolve($statement->expr);
                    [$sources, $sanitized] = $this->mergeEntries(
                        ['taintedSources' => $sources, 'sanitizedFor' => $sanitized],
                        $resolved,
                    );
                    $found = true;
                }
            }
        }

        if (!$found) {
            return ['taintedSources' => [], 'sanitizedFor' => []];
        }

        return ['taintedSources' => $sources, 'sanitizedFor' => $sanitized];
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
