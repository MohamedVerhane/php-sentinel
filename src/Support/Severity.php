<?php

declare(strict_types=1);

namespace PhpSentinel\Support;

/**
 * Represents the severity level of a security finding.
 *
 * The enum cases are ordered from least to most severe. Use {@see rank()} to
 * compare severities so the scanner can filter findings below a configured
 * threshold.
 */
enum Severity: string
{
    case INFO = 'INFO';
    case LOW = 'LOW';
    case MEDIUM = 'MEDIUM';
    case HIGH = 'HIGH';
    case CRITICAL = 'CRITICAL';

    /**
     * Returns a numeric rank used to compare severities.
     *
     * A higher rank means a more severe level.
     */
    public function rank(): int
    {
        return match ($this) {
            self::INFO => 0,
            self::LOW => 1,
            self::MEDIUM => 2,
            self::HIGH => 3,
            self::CRITICAL => 4,
        };
    }

    /**
     * Returns true when this severity is at least as severe as the given one.
     */
    public function isAtLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    /**
     * Resolves a severity from a case-insensitive name.
     *
     * @throws \InvalidArgumentException when the name does not match any case.
     */
    public static function fromName(string $name): self
    {
        $normalized = strtoupper(trim($name));

        foreach (self::cases() as $case) {
            if ($case->value === $normalized) {
                return $case;
            }
        }

        throw new \InvalidArgumentException(sprintf(
            'Unknown severity "%s". Expected one of: %s.',
            $name,
            implode(', ', array_map(static fn (self $s): string => $s->value, self::cases())),
        ));
    }
}
