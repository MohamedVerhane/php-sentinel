<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpSentinel\Support\Finding;
use PhpSentinel\Support\Severity;

/**
 * Detects local / remote file inclusion: user-controlled data influencing the
 * path of an `include`, `include_once`, `require` or `require_once` statement.
 *
 * Static paths (for example `require __DIR__ . '/config.php'`) are never
 * flagged. Only paths derived from user input are reported.
 */
final class FileInclusionRule extends AbstractRule
{
    public const ID = 'SEC004';

    private const SINK_CATEGORY = 'file-inclusion';

    public function id(): string
    {
        return self::ID;
    }

    public function name(): string
    {
        return 'File Inclusion';
    }

    public function description(): string
    {
        return 'User-controlled input influences the path of an include or require statement, which can allow an '
            . 'attacker to include arbitrary local files (Local File Inclusion) or, when remote inclusion is enabled, '
            . 'remote files (Remote File Inclusion).';
    }

    public function severity(): Severity
    {
        return Severity::HIGH;
    }

    public function cwe(): ?string
    {
        return 'CWE-98';
    }

    public function remediation(): string
    {
        return 'Never use user input directly in include/require paths. Resolve paths against an explicit allow-list '
            . 'of known values, disable allow_url_include, restrict include paths, and avoid dynamic include paths '
            . 'altogether when possible.';
    }

    public function analyze(Node $node, RuleContext $context): array
    {
        if (!$node instanceof Expr\Include_) {
            return [];
        }

        $path = $node->expr;
        if (!$context->analyzer->isDangerous($path, self::SINK_CATEGORY)) {
            return [];
        }

        $sources = $context->analyzer->sourcesOf($path);
        $sourceList = $sources === [] ? 'User-controlled' : 'User-controlled input (' . implode(', ', $sources) . ')';

        return [
            $this->makeFinding(
                'Potential File Inclusion',
                sprintf(
                    '%s influences an include/require path. Use an explicit allow-list of known paths.',
                    $sourceList,
                ),
                $context,
                $node,
                ['sinks' => ['file-inclusion'], 'sources' => $sources],
            ),
        ];
    }
}
