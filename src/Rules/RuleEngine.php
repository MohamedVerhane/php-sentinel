<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpSentinel\Support\Finding;

/**
 * Runs a set of rules against every node of a parsed AST.
 *
 * The engine traverses the AST once (using php-parser's {@see NodeFinder}) and
 * invokes each enabled rule on each node, collecting the findings into a flat
 * list. Rules that do not care about a node return an empty list.
 */
final class RuleEngine
{
    /**
     * @param list<RuleInterface> $rules
     */
    public function __construct(
        private array $rules,
    ) {
    }

    /**
     * Runs the enabled rules over the AST and returns all findings.
     *
     * @param list<Node> $ast
     *
     * @return list<Finding>
     */
    public function run(array $ast, RuleContext $context): array
    {
        $findings = [];
        $nodes = (new NodeFinder())->find($ast, static fn (Node $node): bool => true);

        foreach ($nodes as $node) {
            foreach ($this->rules as $rule) {
                foreach ($rule->analyze($node, $context) as $finding) {
                    $findings[] = $finding;
                }
            }
        }

        return $findings;
    }
}
