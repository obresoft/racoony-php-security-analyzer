<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Attribute\CWE;

#[CWE('352', 'Cross-Site Request Forgery (CSRF)', 'https://cwe.mitre.org/data/definitions/352.html')]
final class LaravelCrossSiteRequestForgeryCsrf extends AbstractLaravelRequiredWebMiddlewareRule
{
    protected function requiredMiddleware(): string
    {
        return 'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken';
    }

    protected function cwe(): string
    {
        return CWE::CWE_352;
    }

    protected function message(): string
    {
        return 'The VerifyCsrfToken middleware is missing from the "web" group. Requests may be vulnerable to CSRF.';
    }
}
