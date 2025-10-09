<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelSensitiveCookieExemptions;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use Obresoft\Racoony\Tests\LaravelRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelSensitiveCookieExemptions::class)]
final class LaravelSensitiveCookieExemptionsTest extends AbstractTestCase implements LaravelRule
{
    /**
     * @param list<Insight> $expected
     * @throws Exception
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function test(string $code, array $expected, ApplicationData $app): void
    {
        $this->runTest($code, $expected, __FILE__, $app);
    }

    /**
     * @return iterable<array{string, list<Insight>, ApplicationData}>
     */
    public static function provideCases(): iterable
    {
        yield 'direct session in except' => [
            <<<'PHP'
                <?php

                namespace App\Http\Middleware;

                use Illuminate\Cookie\Middleware\EncryptCookies as Middleware;

                class EncryptCookies extends Middleware
                {
                    protected $except = [
                        'session',
                        'locale',
                    ];
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'Sensitive cookie (session) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield 'remember_web wildcard in except' => [
            <<<'PHP'
                <?php

                namespace App\Http\Middleware;

                use Illuminate\Cookie\Middleware\EncryptCookies as Middleware;

                class EncryptCookies extends Middleware
                {
                    protected $except = [
                        'remember_web_abc123',
                        'remember_web_xyz',
                    ];
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'Sensitive cookie (remember_web_abc123) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'Sensitive cookie (remember_web_xyz) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield 'token names in except' => [
            <<<'PHP'
                <?php

                namespace App\Http\Middleware;

                use Illuminate\Cookie\Middleware\EncryptCookies as Middleware;

                class EncryptCookies extends Middleware
                {
                    protected $except = [
                        'access_token',
                        'refresh_token',
                        'jwt',
                    ];
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'Sensitive cookie (access_token) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'Sensitive cookie (refresh_token) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'Sensitive cookie (jwt) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield 'laravel_session exact in except' => [
            <<<'PHP'
                <?php

                namespace App\Http\Middleware;

                use Illuminate\Cookie\Middleware\EncryptCookies as Middleware;

                class EncryptCookies extends Middleware
                {
                    protected $except = [
                        'laravel_session',
                    ];
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'Sensitive cookie (laravel_session) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http\Middleware;

                use Illuminate\Cookie\Middleware\EncryptCookies as Middleware;

                class EncryptCookies extends Middleware
                {
                    protected $except = [
                        'locale',
                        'theme',
                    ];
                }
                PHP,
            [],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http\Middleware;

                use Illuminate\Cookie\Middleware\EncryptCookies as Middleware;

                class EncryptCookies extends Middleware
                {
                    // no $except defined
                }
                PHP,
            [],
            new ApplicationData('laravel', '10'),
        ];
    }
}
