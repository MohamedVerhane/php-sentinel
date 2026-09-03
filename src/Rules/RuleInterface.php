<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpSentinel\Support\Finding;
use PhpSentinel\Support\Severity;

/**
 * A security rule that inspects AST nodes and reports findings.
 *
 * Rules are stateless with respect to a scan: each rule exposes stable metadata
 * and an {@see analyze()} method that is invoked once per visited AST node. A
 * rule returns an empty list when the node is not interesting or is safe.
 */
interface RuleInterface
{
    /**
     * Stable machine-readable rule identifier (e.g. "SEC001").
     */
    public function id(): string;

    /**
     * Human readable rule name.
     */
    public function name(): string;

    /**
     * Human readable description of the vulnerability the rule detects.
     */
    public function description(): string;

    /**
     * The default severity assigned to findings produced by this rule.
     */
    public function severity(): Severity;

    /**
     * The Common Weakness Enumeration identifier (e.g. "CWE-89") or null.
     */
    public function cwe(): ?string;

    /**
     * Remediation guidance shown to developers for findings of this rule.
     */
    public function remediation(): string;

    /**
     * Analyzes a single AST node and returns the findings it detects.
     *
     * Implementations should return an empty array for nodes they do not care
     * about and never throw for malformed input.
     *
     * @return list<Finding>
     */
    public function analyze(Node $node, RuleContext $context): array;
}
