<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpSentinel\Support\Finding;
use PhpSentinel\Support\Severity;

/**
 * Detects unsafe file upload handling.
 *
 * This rule inspects uses of `$_FILES` and `move_uploaded_file()` and reports,
 * conservatively, two classes of potential issues:
 *
 *  1. A moved file's destination/name is derived directly from user-controlled
 *     `$_FILES[...]['name']` data without validation.
 *  2. `move_uploaded_file()` is called in a scope that performs no detectable
 *     file type / MIME / extension validation at all.
 *
 * The rule never claims that a vulnerability definitely exists — static
 * analysis cannot prove the absence or insufficiency of validation performed
 * elsewhere (e.g. in a framework validator), so findings are worded as
 * "potential".
 */
final class UnsafeUploadRule extends AbstractRule
{
    public const ID = 'SEC005';

    /**
     * Constructs that, when operating on the specific `$_FILES` upload being
     * moved, signal that the file is genuinely being validated. Grouped by the
     * kind of validation they perform so that unrelated tallies (e.g. a
     * `pathinfo()` on some other value) are not mistaken for proof of
     * validation.
     *
     * @var array<string, list<string>>
     */
    private const VALIDATION_FUNCTIONS = [
        'mime' => [
            'getimagesize',
            'finfo_open',
            'finfo_file',
            'mime_content_type',
            'exif_imagetype',
        ],
        'extension' => [
            'pathinfo',
            'str_ends_with',
            'str_contains',
        ],
        'authenticity' => [
            'is_uploaded_file',
        ],
    ];

    public function id(): string
    {
        return self::ID;
    }

    public function name(): string
    {
        return 'Unsafe File Upload';
    }

    public function description(): string
    {
        return 'File uploads are handled without (detectable) validation of the file type, MIME type or extension, '
            . 'or the uploaded file name is derived directly from user input. This can allow an attacker to upload '
            . 'executable files or overwrite arbitrary paths.';
    }

    public function severity(): Severity
    {
        return Severity::MEDIUM;
    }

    public function cwe(): ?string
    {
        return 'CWE-434';
    }

    public function remediation(): string
    {
        return 'Validate uploads: check the MIME type and real file content (e.g. finfo_file / getimagesize), whitelist '
            . 'allowed extensions and MIME types, generate a random destination name (never trust $_FILES name), '
            . 'store uploads outside the web root or in a dedicated media directory, and disable execution of '
            . 'uploaded files.';
    }

    public function analyze(Node $node, RuleContext $context): array
    {
        $findings = [];

        if (
            $node instanceof Expr\FuncCall
            && $node->name instanceof Node\Name
            && $this->functionName($node->name) === 'move_uploaded_file'
        ) {
            $findings = array_merge($findings, $this->analyzeMoveUploaded($node, $context));
        }

        return $findings;
    }

    /**
     * @return list<Finding>
     */
    private function analyzeMoveUploaded(Expr\FuncCall $node, RuleContext $context): array
    {
        $findings = [];
        $scope = $this->findContainingScope($node, $context->ast);
        $scopeNodes = $this->scopeStatements($scope, $context->ast);
        $assignments = $this->collectAssignments($scopeNodes);

        // Issue 1: destination/name derived from user-controlled file name.
        $destination = $this->destinationExpression($node);

        if ($destination !== null) {
            $resolved = $this->resolveValue($destination, $assignments);

            if ($resolved !== null && $this->referencesFiles($resolved)) {
                $findings[] = $this->makeFinding(
                    'Unsafe Upload Destination',
                    'The uploaded file destination/name is derived from user-controlled $_FILES data without generating '
                        . 'a safe random name. Use a server-generated name and validate the real file type.',
                    $context,
                    $destination,
                    ['issue' => 'user-controlled-filename'],
                );
            }
        }

        // Issue 2: no detectable validation of the specific upload being moved,
        // happening before the move. Validation that operates on a different
        // $_FILES entry, or that runs after the move, cannot protect this file.
        $uploadKey = $this->uploadKeyOf($node, $assignments);

        if (!$this->hasValidation($scopeNodes, $uploadKey, $node->getStartLine(), $assignments)) {
            $this->appendFinding($findings, $this->makeFinding(
                'Upload Without File-Type Validation',
                'move_uploaded_file() is used without detectable validation of the file type, MIME type or extension. '
                    . 'Validate the real content (e.g. finfo_file) and whitelist allowed types before storing the file.',
                $context,
                $node,
                ['issue' => 'missing-validation'],
            ));
        }

        return $findings;
    }

    /**
     * Returns the statements belonging to the given scope, falling back to the
     * whole file when the call is not inside a function-like scope.
     *
     * @param list<Node> $ast
     *
     * @return list<Node>
     */
    private function scopeStatements(Stmt|Expr\Closure|null $scope, array $ast): array
    {
        if ($scope === null) {
            return $ast;
        }

        if (
            $scope instanceof Stmt\Function_
            || $scope instanceof Stmt\ClassMethod
            || $scope instanceof Expr\Closure
            || $scope instanceof Stmt\Namespace_
        ) {
            return $scope->stmts ?? [];
        }

        return [$scope];
    }

    /**
     * Builds a map of variable name => assigned expression for the given
     * statements (top-level assignments only).
     *
     * @param list<Node> $nodes
     *
     * @return array<string, Expr>
     */
    private function collectAssignments(array $nodes): array
    {
        $assignments = [];

        foreach ($nodes as $node) {
            if (!$node instanceof Stmt\Expression || !$node->expr instanceof Expr\Assign) {
                continue;
            }

            $assign = $node->expr;
            if ($assign->var instanceof Expr\Variable && is_string($assign->var->name)) {
                if ($assign->expr instanceof Expr) {
                    $assignments[$assign->var->name] = $assign->expr;
                }
            }
        }

        return $assignments;
    }

    /**
     * Follows a simple variable reference through the collected assignments.
     *
     * @param array<string, Expr> $assignments
     */
    private function resolveValue(Expr $expr, array $assignments): Expr
    {
        $current = $expr;

        for ($depth = 0; $depth < 4; $depth++) {
            if ($current instanceof Expr\Variable && is_string($current->name) && isset($assignments[$current->name])) {
                $current = $assignments[$current->name];
                continue;
            }

            break;
        }

        return $current;
    }

    private function destinationExpression(Expr\FuncCall $node): ?Expr
    {
        $args = $node->getArgs();
        if (isset($args[1]) && $args[1]->value instanceof Expr) {
            return $args[1]->value;
        }

        return null;
    }

    private function referencesFiles(Expr $expr): bool
    {
        return (new NodeFinder())->findFirst([$expr], static function (Node $candidate) {
            return $candidate instanceof Expr\Variable
                && is_string($candidate->name)
                && strcasecmp($candidate->name, '_FILES') === 0;
        }) !== null;
    }

    /**
     * Determines which `$_FILES` upload key the moved file's source belongs to,
     * following chained variable assignments (e.g. the value of `$tmp` when it
     * is assigned from `$_FILES['avatar']['tmp_name']`).
     *
     * @param array<string, Expr> $assignments
     */
    private function uploadKeyOf(Expr\FuncCall $node, array $assignments): ?string
    {
        $args = $node->getArgs();
        if (!isset($args[0]) || !$args[0]->value instanceof Expr) {
            return null;
        }

        $resolved = $this->resolveValue($args[0]->value, $assignments);

        return $this->filesKeyOf($resolved);
    }

    /**
     * Returns the string literal `$_FILES` key of an expression, or null when
     * the expression does not reference a directly identifiable upload field.
     */
    private function filesKeyOf(Expr $expr): ?string
    {
        $dims = (new NodeFinder())->find($expr, static function (Node $candidate) {
            return $candidate instanceof Expr\ArrayDimFetch
                && $candidate->var instanceof Expr\Variable
                && is_string($candidate->var->name)
                && strcasecmp($candidate->var->name, '_FILES') === 0;
        });

        foreach ($dims as $dim) {
            if ($dim instanceof Expr\ArrayDimFetch && $dim->dim instanceof Node\Scalar\String_) {
                return $dim->dim->value;
            }
        }

        return null;
    }

    /**
     * Returns true when a genuinely relevant validation (MIME/content,
     * extension, authenticity or size) of the upload being moved appears on a
     * line at or before `$moveLine`. When the upload key is unknown, a
     * validation of any `$_FILES` entry is accepted as a fallback, which keeps
     * the check conservative without treating unrelated tallies as proof.
     *
     * @param list<Node>                $statements
     * @param array<string, Expr>       $assignments
     */
    private function hasValidation(array $statements, ?string $uploadKey, int $moveLine, array $assignments): bool
    {
        $exprs = (new NodeFinder())->find($statements, static fn (Node $candidate): bool => $candidate instanceof Expr);

        foreach ($exprs as $expr) {
            if (!$expr instanceof Expr || $expr->getStartLine() > $moveLine) {
                continue;
            }

            if ($expr instanceof Expr\BinaryOp) {
                foreach ([$expr->left, $expr->right] as $operand) {
                    if (
                        $operand instanceof Node\Scalar\String_
                        && str_contains($operand->value, 'image/')
                        && $this->expressionReferencesKey($expr, $uploadKey, $assignments)
                    ) {
                        return true;
                    }

                    if (
                        $operand instanceof Expr\ArrayDimFetch
                        && $this->dimensionName($operand) === 'size'
                        && $this->expressionReferencesKey($operand, $uploadKey, $assignments)
                    ) {
                        return true;
                    }
                }
            }

            if (
                $expr instanceof Expr\FuncCall
                && $expr->name instanceof Node\Name
                && $this->categoryOf($expr->name->toLowerString()) !== null
                && $this->expressionReferencesKey($expr, $uploadKey, $assignments)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true when the given expression (a potential validation construct)
     * operates on the `$_FILES` upload being moved, following chained variable
     * assignments. When the upload key is unknown, any `$_FILES` reference is
     * accepted as a fallback so the check stays conservative.
     *
     * @param array<string, Expr> $assignments
     */
    private function expressionReferencesKey(Expr $expr, ?string $uploadKey, array $assignments): bool
    {
        $refs = (new NodeFinder())->find($expr, static function (Node $candidate) {
            return $candidate instanceof Expr\Variable || $candidate instanceof Expr\ArrayDimFetch;
        });

        if ($refs === []) {
            return false;
        }

        foreach ($refs as $ref) {
            if (!$ref instanceof Expr) {
                continue;
            }
            $resolved = $this->resolveValue($ref, $assignments);
            $key = $this->filesKeyOf($resolved);

            if ($key === null) {
                continue;
            }

            if ($uploadKey === null || $key === $uploadKey) {
                return true;
            }
        }

        return false;
    }

    private function dimensionName(Expr\ArrayDimFetch $dim): ?string
    {
        return $dim->dim instanceof Node\Scalar\String_ ? strtolower($dim->dim->value) : null;
    }

    private function categoryOf(string $functionName): ?string
    {
        foreach (self::VALIDATION_FUNCTIONS as $category => $functions) {
            if (in_array($functionName, $functions, true)) {
                return $category;
            }
        }

        return null;
    }

    /**
     * Finds the innermost function-like scope enclosing the given node.
     *
     * @param list<Node> $ast
     *
     * @return Stmt|Expr\Closure|null
     */
    private function findContainingScope(Node $node, array $ast): Stmt|Expr\Closure|null
    {
        $targetLine = $node->getStartLine();
        $best = null;

        (new NodeFinder())->findFirst($ast, function (Node $candidate) use (&$best, $targetLine): bool {
            $isScope = $candidate instanceof Stmt\Function_
                || $candidate instanceof Stmt\ClassMethod
                || $candidate instanceof Expr\Closure;

            if (!$isScope) {
                return false;
            }

            if ($candidate->getStartLine() <= $targetLine && $candidate->getEndLine() >= $targetLine) {
                $best = $candidate;
            }

            return false;
        });

        return $best;
    }

    /**
     * Appends a finding unless an identical one is already present.
     *
     * @param list<Finding> $findings
     */
    private function appendFinding(array &$findings, Finding $finding): void
    {
        foreach ($findings as $existing) {
            if (
                $existing->ruleId === $finding->ruleId
                && $existing->file === $finding->file
                && $existing->line === $finding->line
                && $existing->title === $finding->title
            ) {
                return;
            }
        }

        $findings[] = $finding;
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
