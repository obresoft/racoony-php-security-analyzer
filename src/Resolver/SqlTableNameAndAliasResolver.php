<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver;

use Obresoft\Racoony\Resolver\Dto\TableReferenceDto;

use function preg_match;
use function preg_replace;
use function strlen;
use function trim;

final class SqlTableNameAndAliasResolver
{
    public function resolveFromString(?string $tableExpression): ?TableReferenceDto
    {
        if (null === $tableExpression) {
            return null;
        }

        $normalizedExpression = $this->normalizeWhitespace($tableExpression);
        if ('' === $normalizedExpression) {
            return null;
        }

        $pattern = '/^
            (?P<table>[A-Za-z0-9_]+)
            (?:
                \s+
                (?:as\s+)?
                (?P<alias>`?[A-Za-z0-9_]+`?)
            )?
        $/ix';

        if (1 !== preg_match($pattern, $normalizedExpression, $matches)) {
            return null;
        }

        $tableName = $matches['table'];
        $alias = $matches['alias'] ?? null;

        if (null !== $alias) {
            $alias = $this->stripBackticks($alias);
        }

        return new TableReferenceDto(
            tableName: $tableName,
            alias: $alias,
        );
    }

    private function normalizeWhitespace(string $value): string
    {
        $value = trim($value);

        return (string)preg_replace('/\s+/', ' ', $value);
    }

    private function stripBackticks(string $value): string
    {
        $value = trim($value);

        if (strlen($value) >= 2 && '`' === $value[0] && '`' === $value[strlen($value) - 1]) {
            return substr($value, 1, -1);
        }

        return $value;
    }
}
