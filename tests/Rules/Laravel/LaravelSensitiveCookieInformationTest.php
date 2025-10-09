<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelSensitiveCookieInformation;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use Obresoft\Racoony\Tests\LaravelRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelSensitiveCookieInformation::class)]
final class LaravelSensitiveCookieInformationTest extends AbstractTestCase implements LaravelRule
{
    /**
     * @param list<Insight> $expected
     * @throws Exception
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function test(string $code, array $expected, ?ApplicationData $applicationData = null): void
    {
        $this->runTest($code, $expected, __FILE__, $applicationData);
    }

    /**
     * @return iterable<int|string, array{0: string, 1?: list<Insight>, 2?: ApplicationData}>
     */
    public static function provideCases(): iterable
    {
        yield [
            <<<'PHP'
                <?php

                namespace App\Http;

                use Illuminate\Foundation\Http\Kernel as HttpKernel;

                class Kernel extends HttpKernel
                {
                    protected $middleware = [
                        \App\Http\Middleware\TrustProxies::class,
                    ];

                    protected $middlewareGroups = [
                        'web' => [
                            \App\Http\Middleware\EncryptCookies::class,
                        ],

                        'api' => [
                            'throttle:api',
                        ],
                    ];
                }

                PHP,
            [
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http;

                use Illuminate\Foundation\Http\Kernel as HttpKernel;

                class Kernel extends HttpKernel
                {
                    protected $middleware = [
                        \App\Http\Middleware\TrustProxies::class,
                    ];

                    protected $middlewareGroups = [
                        'web' => [
                        ],

                        'api' => [
                            'throttle:api',
                        ],
                    ];
                }

                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_315,
                    'The EncryptCookies middleware is missing from the "web" group. Sensitive cookie data may be stored in cleartext.
[CWE-315: Cleartext Storage of Sensitive Information in a Cookie] See: https://cwe.mitre.org/data/definitions/315.html',
                    13,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http;

                use Illuminate\Foundation\Http\Kernel as HttpKernel;
                use App\Http\Middleware\EncryptCookies;

                class Kernel extends HttpKernel
                {
                    protected $middleware = [
                        \App\Http\Middleware\TrustProxies::class,
                    ];

                    protected $middlewareGroups = [
                        'web' => [
                           EncryptCookies::class,
                        ],

                        'api' => [
                            'throttle:api',
                        ],
                    ];
                }

                PHP,
            [
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http;

                use Illuminate\Foundation\Http\Kernel as HttpKernel;
                use App\Http\Middleware\EncryptCookies as ENC;

                class Kernel extends HttpKernel
                {
                    protected $middleware = [
                        \App\Http\Middleware\TrustProxies::class,
                    ];

                    protected $middlewareGroups = [
                        'web' => [
                           ENC::class,
                        ],

                        'api' => [
                            'throttle:api',
                        ],
                    ];
                }

                PHP,
            [
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http;

                use Illuminate\Foundation\Http\Kernel as HttpKernel;
                use App\Http\Middleware\CustomEncryptCookies;

                class Kernel extends HttpKernel
                {
                    protected $middleware = [
                        \App\Http\Middleware\TrustProxies::class,
                    ];

                    protected $middlewareGroups = [
                        'web' => [
                           CustomEncryptCookies::class,
                        ],

                        'api' => [
                            'throttle:api',
                        ],
                    ];
                }

                PHP,
            [
            ],
            new ApplicationData('laravel', '10'),
        ];
    }
}
