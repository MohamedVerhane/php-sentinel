<?php

declare(strict_types=1);

namespace PhpSentinel\DataFlow;

/**
 * Describes a user-controlled source of data (typically a PHP superglobal).
 *
 * A source marks where external input enters the program. The analyzer treats
 * reads from these locations as tainted unless a sanitizer is applied.
 */
final readonly class Source
{
    /**
     * Standard sources recognised by the analyzer.
     *
     * @var list<string>
     */
    public const STANDARD = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES'];

    public function __construct(
        public string $name,
    ) {
    }

    public static function get(): self
    {
        return new self('$_GET');
    }

    public static function post(): self
    {
        return new self('$_POST');
    }

    public static function request(): self
    {
        return new self('$_REQUEST');
    }

    public static function cookie(): self
    {
        return new self('$_COOKIE');
    }

    public static function server(): self
    {
        return new self('$_SERVER');
    }

    public static function files(): self
    {
        return new self('$_FILES');
    }
}
