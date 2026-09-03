<?php

declare(strict_types=1);

namespace PhpSentinel\Exception;

/**
 * Thrown when source code cannot be read or scanned.
 *
 * This exception does not abort the whole scan: the scanner reports unreadable
 * files as skipped and continues with the remaining files.
 */
final class ScanException extends \RuntimeException implements SentinelException
{
}
