<?php

declare(strict_types=1);

namespace PhpSentinel\Exception;

/**
 * Thrown when user input (CLI arguments or configuration) is invalid.
 *
 * The CLI maps this to exit code 2.
 */
final class InvalidInputException extends \InvalidArgumentException implements SentinelException
{
}
