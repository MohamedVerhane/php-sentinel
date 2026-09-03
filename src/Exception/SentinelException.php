<?php

declare(strict_types=1);

namespace PhpSentinel\Exception;

/**
 * Base marker interface for all PHP Sentinel runtime exceptions.
 *
 * Catching this interface lets callers handle any domain-specific error raised
 * by the scanner without depending on concrete exception classes.
 */
interface SentinelException
{
}
