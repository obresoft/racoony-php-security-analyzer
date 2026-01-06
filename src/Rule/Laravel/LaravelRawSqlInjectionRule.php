<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Attribute\CWE;

#[CWE(
    '89',
    "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    'https://cwe.mitre.org/data/definitions/89.html',
)]
final class LaravelRawSqlInjectionRule extends AbstractSqlInjectionRule
{
    protected function methodsToCheck(): array
    {
        return [
            // 'where', need to fix for closure test
            'orwhere',
            // 'update',
            'insertusing',
            // 'select',
            'selectraw',
            'statement',
            'raw',
            'whereraw',
            'fromraw',
        ];
    }
}
