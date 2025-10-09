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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelSensitiveCookieExemptions::class)]
final class LaravelSensitiveCookieGraterThan10ExemptionsTest extends AbstractTestCase
{
    /**
     * @param list<Insight> $expected
     * @throws Exception
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function test(string $code, array $expected, ApplicationData $app): void
    {
        $this->runTest($code, $expected, 'bootstrap/app.php', $app);
    }

    /**
     * @return iterable<array{string, list<Insight>, ApplicationData}>
     */
    public static function provideCases(): iterable
    {
        yield [
            <<<'PHP'
                <?php

                declare(strict_types=1);

                use Illuminate\Foundation\Application;
                use Illuminate\Foundation\Configuration\Exceptions;
                use Illuminate\Foundation\Configuration\Middleware;

                return Application::configure(basePath: dirname(__DIR__))
                    ->withRouting(
                        web: __DIR__ . '/../routes/web.php',
                    )->withMiddleware(static function (Middleware $middleware): void {
                        $middleware->encryptCookies([
                            'name_will_not_encrypt',
                        ]);
                    })->create();
                PHP,
            [
            ],
            new ApplicationData('laravel', '11'),
        ];

        yield [
            <<<'PHP'
                <?php

                declare(strict_types=1);

                use Illuminate\Foundation\Application;
                use Illuminate\Foundation\Configuration\Exceptions;
                use Illuminate\Foundation\Configuration\Middleware;

                return Application::configure(basePath: dirname(__DIR__))
                    ->withRouting(
                        web: __DIR__ . '/../routes/web.php',
                    )->withMiddleware(static function (Middleware $middleware): void {
                        $middleware->encryptCookies([
                           'session',
                        ]);
                    })->create();
                PHP,
            [
                new Vulnerability(
                    'bootstrap/app.php',
                    CWE::CWE_315,
                    'Sensitive cookie (session) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    13,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '11'),
        ];

        yield [
            <<<'PHP'
                <?php

                declare(strict_types=1);

                use Illuminate\Foundation\Application;
                use Illuminate\Foundation\Configuration\Exceptions;
                use Illuminate\Foundation\Configuration\Middleware;

                $cookies = ['session',];
                return Application::configure(basePath: dirname(__DIR__))
                    ->withRouting(
                        web: __DIR__ . '/../routes/web.php',
                    )->withMiddleware(static function (Middleware $middleware): void {
                        $middleware->encryptCookies($cookies);
                    })->create();
                PHP,
            [
                new Vulnerability(
                    'bootstrap/app.php',
                    CWE::CWE_315,
                    'Sensitive cookie (session) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '11'),
        ];
    }
}
