<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelCrossSiteRequestForgeryCsrf;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use Obresoft\Racoony\Tests\LaravelRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelCrossSiteRequestForgeryCsrf::class)]
final class LaravelCrossSiteRequestForgeryCsrfTest extends AbstractTestCase implements LaravelRule
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
                            \App\Http\Middleware\VerifyCsrfToken::class,
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
                    CWE::CWE_352,
                    'The VerifyCsrfToken middleware is missing from the "web" group. Requests may be vulnerable to CSRF.
[CWE-352: Cross-Site Request Forgery (CSRF)] See: https://cwe.mitre.org/data/definitions/352.html',
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
                use App\Http\Middleware\VerifyCsrfToken;

                class Kernel extends HttpKernel
                {
                    protected $middleware = [
                        \App\Http\Middleware\TrustProxies::class,
                    ];

                    protected $middlewareGroups = [
                        'web' => [
                           VerifyCsrfToken::class,
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
                use App\Http\Middleware\VerifyCsrfToken As Scrf;

                class Kernel extends HttpKernel
                {
                    protected $middleware = [
                        \App\Http\Middleware\TrustProxies::class,
                    ];

                    protected $middlewareGroups = [
                        'web' => [
                           Scrf::class,
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
