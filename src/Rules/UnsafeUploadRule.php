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
     * Constructs that, when present in the same scope as a move_uploaded_file
     * call, signal that some file type validation is likely being performed.
     *
     * @var list<string>
     */
    private const VALIDATION_FUNCTIONS = [
        'getimagesize',
        'finfo_open',
        'finfo_file',
        'mime_content_type',
        'exif_imagetype',
        'pathinfo',
        'in_array',
        'is_uploaded_file',
        'substr',
        'str_ends_with',
        'str_contains',
        'preg_match',
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
        $resolved = $destination !== null ? $this->resolveValue($destination, $assignments) : null;
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

        // Issue 2: no detectable validation in the same scope.
        if (!$this->hasValidation($scopeNodes)) {
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
     * @param list<Node> $statements
     */
    private function hasValidation(array $statements): bool
    {
        $found = (new NodeFinder())->find($statements, static fn (Node $candidate): bool => (
            $candidate instanceof Expr\FuncCall
            && $candidate->name instanceof Node\Name
            && in_array(
                $candidate->name->toLowerString(),
                self::VALIDATION_FUNCTIONS,
                true,
            )
        ));

        // Also detect direct MIME comparisons such as $mime === 'image/png'.
        $mimeLiteral = (new NodeFinder())->find(
            $statements,
            static function (Node $candidate): bool {
                if ($candidate instanceof Expr\BinaryOp) {
                    foreach ([$candidate->left, $candidate->right] as $operand) {
                        if ($operand instanceof Node\Scalar\String_ && str_contains($operand->value, 'image/')) {
                            return true;
                        }
                    }
                }

                return false;
            },
        );

        return $found !== [] || $mimeLiteral !== [];
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
