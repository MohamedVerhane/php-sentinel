<?php

declare(strict_types=1);

namespace PhpSentinel\Parser;

use PhpParser\Error;
use PhpParser\Node\Stmt;
use PhpParser\Parser;
use PhpParser\ParserFactory;

/**
 * Adapts nikic/php-parser into the {@see ParserInterface} contract.
 *
 * The parser reads PHP source and produces an AST. It never executes the code
 * it parses, and it converts parser diagnostics into a {@see ParseResult}
 * instead of letting a single invalid file abort the whole scan.
 */
final class PhpParser implements ParserInterface
{
    private Parser $parser;

    public function __construct(?Parser $parser = null)
    {
        $this->parser = $parser ?? (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function parse(string $code, ?string $fileHint = null): ParseResult
    {
        try {
            /** @var list<Stmt> $statements */
            $statements = $this->parser->parse($code);

            return ParseResult::success($statements);
        } catch (Error $error) {
            $line = $error->getStartLine();
            $column = $error->getStartColumn($code);

            $prefix = $fileHint !== null && $fileHint !== ''
                ? sprintf('%s:%d:%d ', $fileHint, $line, $column)
                : sprintf('line %d, column %d: ', $line, $column);

            return ParseResult::failure($prefix . $error->getRawMessage(), $line, $column);
        }
    }
}
