<?php

declare(strict_types=1);

namespace PhpSentinel\Support;

/**
 * An immutable value object describing a single security finding.
 *
 * A finding is produced by a rule when it detects a potential vulnerability.
 * Instances are immutable: all properties are promoted readonly and the object
 * cannot be mutated after construction.
 */
final readonly class Finding
{
    /**
     * @param array<string, mixed> $metadata additional rule specific data
     */
    public function __construct(
        public string $ruleId,
        public string $ruleName,
        public Severity $severity,
        public string $title,
        public string $message,
        public string $description,
        public string $recommendation,
        public string $file,
        public int $line,
        public int $column,
        public ?string $codeSnippet,
        public ?string $cwe,
        public array $metadata = [],
    ) {
    }

    public function ruleId(): string
    {
        return $this->ruleId;
    }

    public function ruleName(): string
    {
        return $this->ruleName;
    }

    public function severity(): Severity
    {
        return $this->severity;
    }

    public function title(): string
    {
        return $this->title;
    }

    public function message(): string
    {
        return $this->message;
    }

    public function description(): string
    {
        return $this->description;
    }

    public function recommendation(): string
    {
        return $this->recommendation;
    }

    public function file(): string
    {
        return $this->file;
    }

    public function line(): int
    {
        return $this->line;
    }

    public function column(): int
    {
        return $this->column;
    }

    public function codeSnippet(): ?string
    {
        return $this->codeSnippet;
    }

    public function cwe(): ?string
    {
        return $this->cwe;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    /**
     * Returns whether this finding is at least as severe as the given threshold.
     */
    public function meetsThreshold(Severity $threshold): bool
    {
        return $this->severity->isAtLeast($threshold);
    }
}
