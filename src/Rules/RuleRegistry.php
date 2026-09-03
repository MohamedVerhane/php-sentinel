<?php

declare(strict_types=1);

namespace PhpSentinel\Rules;

use PhpSentinel\Exception\InvalidInputException;

/**
 * Registry of all available security rules.
 *
 * A registry owns its rule instances and can resolve which rules to enable
 * based on configuration. Adding a new rule means instantiating it here (and,
 * optionally, registering its ID in the default configuration) — the scanner
 * core does not need to change.
 */
final class RuleRegistry
{
    /**
     * @var array<string, RuleInterface>
     */
    private array $rules;

    /**
     * @param iterable<RuleInterface> $rules
     */
    public function __construct(iterable $rules = [])
    {
        $this->rules = [];

        foreach ($rules as $rule) {
            $this->rules[$rule->id()] = $rule;
        }
    }

    /**
     * Builds a registry pre-populated with every bundled rule.
     */
    public static function withDefaultRules(): self
    {
        return new self([
            new SqlInjectionRule(),
            new XssRule(),
            new CommandInjectionRule(),
            new FileInclusionRule(),
            new UnsafeUploadRule(),
        ]);
    }

    /**
     * Returns all registered rules keyed by rule ID.
     *
     * @return array<string, RuleInterface>
     */
    public function all(): array
    {
        return $this->rules;
    }

    public function has(string $id): bool
    {
        return isset($this->rules[$id]);
    }

    public function get(string $id): ?RuleInterface
    {
        return $this->rules[$id] ?? null;
    }

    /**
     * Returns the rules to run for the given set of enabled rule IDs.
     *
     * Unknown enabled rule IDs raise an error so that a typo in the
     * configuration fails fast rather than silently disabling a rule.
     *
     * @param list<string> $enabledIds
     *
     * @return list<RuleInterface>
     */
    public function enabled(array $enabledIds): array
    {
        if ($enabledIds === []) {
            return array_values($this->rules);
        }

        $selected = [];
        foreach ($enabledIds as $id) {
            $rule = $this->get($id);
            if ($rule === null) {
                throw new InvalidInputException(sprintf(
                    'Unknown rule "%s". Available rules: %s.',
                    $id,
                    implode(', ', array_keys($this->rules)),
                ));
            }
            $selected[] = $rule;
        }

        return $selected;
    }
}
