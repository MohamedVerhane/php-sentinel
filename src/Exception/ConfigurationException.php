<?php

declare(strict_types=1);

namespace PhpSentinel\Exception;

use Throwable;

/**
 * Thrown when a project configuration file is invalid or cannot be loaded.
 *
 * The CLI maps this to exit code 2 and prints a user-friendly message.
 */
final class ConfigurationException extends \RuntimeException implements SentinelException
{
    public static function fromThrowable(string $context, Throwable $previous): self
    {
        return new self(
            sprintf('%s: %s', $context, $previous->getMessage()),
            0,
            $previous,
        );
    }
}
