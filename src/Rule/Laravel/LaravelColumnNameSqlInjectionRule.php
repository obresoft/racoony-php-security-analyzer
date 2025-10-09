<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Attribute\CWE;

#[CWE('89', "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", 'https://cwe.mitre.org/data/definitions/89.html')]
final class LaravelColumnNameSqlInjectionRule extends AbstractSqlInjectionRule
{
    protected function methodsToCheck(): array
    {
        return [
            'orderbyraw',
            'groupbyraw',
            'selectraw',
            'whereraw',
            'havingraw',
            'join',
            'from',
            'table',
            'raw',
            'table',
            'get',
            'orwhereraw',
            'unionraw',
            'fromraw',
        ];
    }
}
