<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Attribute\CWE;

#[CWE('315', 'Cleartext Storage of Sensitive Information in a Cookie', 'https://cwe.mitre.org/data/definitions/315.html')]
final class LaravelSensitiveCookieInformation extends AbstractLaravelRequiredWebMiddlewareRule
{
    protected function requiredMiddleware(): string
    {
        return 'Illuminate\Cookie\Middleware\EncryptCookies';
    }

    protected function cwe(): string
    {
        return CWE::CWE_315;
    }

    protected function message(): string
    {
        return 'The EncryptCookies middleware is missing from the "web" group. Sensitive cookie data may be stored in cleartext.';
    }
}
