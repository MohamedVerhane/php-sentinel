<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpSentinel\Support\Finding;

/**
 * Base class that provides the shared finding-builder helper for rules.
 */
abstract class AbstractRule implements RuleInterface
{
    /**
     * Builds a finding pointing at the given node.
     *
     * @param array<string, mixed> $metadata
     */
    protected function makeFinding(
        string $title,
        string $message,
        RuleContext $context,
        Node $node,
        array $metadata = [],
    ): Finding {
        $line = max(1, (int) $node->getStartLine());

        return new Finding(
            ruleId: $this->id(),
            ruleName: $this->name(),
            severity: $this->severity(),
            title: $title,
            message: $message,
            description: $this->description(),
            recommendation: $this->remediation(),
            file: $context->file,
            line: $line,
            column: max(1, $context->columnAt((int) $node->getStartFilePos())),
            codeSnippet: $context->snippet($line),
            cwe: $this->cwe(),
            metadata: $metadata,
        );
    }
}
