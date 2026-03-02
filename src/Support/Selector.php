<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Support;

final class Selector
{
    public static function containsWildcardSelection(array $selectedColumnNames): bool
    {
        foreach ($selectedColumnNames as $selectedColumnName) {
            $trimmed = trim((string)$selectedColumnName);

            if ('*' === $trimmed) {
                return true;
            }

            if (str_ends_with($trimmed, '.*')) {
                return true;
            }
        }

        return false;
    }
}
