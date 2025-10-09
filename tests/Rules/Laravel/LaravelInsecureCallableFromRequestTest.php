<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelInsecureCallableFromRequest;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelInsecureCallableFromRequest::class)]
final class LaravelInsecureCallableFromRequestTest extends AbstractTestCase
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
        yield [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                final class TaskController
                {
                    public function run(Request $r)
                    {
                        $fn = $r->input('do'); // e.g. 'phpinfo' / 'App\\Svc::dumpSecrets'
                        return $fn();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_94,
                    "User-controlled callable from Request is invoked directly. Arbitrary code execution risk (CWE-94).
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    11,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                final class ExecController
                {
                    public function run(Request $r)
                    {
                        $fn = $r->input('do');
                        return \call_user_func($fn);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_94,
                    "User-controlled callable from Request is invoked directly. Arbitrary code execution risk (CWE-94).
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    11,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield 'forward_static_call_array from request pair' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                final class StaticExecController
                {
                    public function run(Request $r)
                    {
                        $class = $r->input('class');
                        $method = $r->input('method');
                        return \forward_static_call_array([$class, $method], []);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_94,
                    "User-controlled callable from Request is invoked directly. Arbitrary code execution risk (CWE-94).
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    11,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield 'dynamic instance method from request' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                final class DynamicController
                {
                    public function run(Request $r)
                    {
                        $method = $r->input('do');
                        return $this->$method();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_94,
                    "User-controlled callable from Request is invoked directly. Arbitrary code execution risk (CWE-94).
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    11,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];

        yield 'whitelist mapping' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                final class SafeController
                {
                    public function run(Request $r)
                    {
                        $action = (string) $r->input('action');
                        $allowed = [
                            'stats' => [\App\Services\Reports::class, 'stats'],
                            'ping'  => fn() => 'pong',
                        ];

                        if (!\array_key_exists($action, $allowed)) {
                            abort(400);
                        }

                        return \call_user_func($allowed[$action]);
                    }
                }
                PHP,
            [],
            new ApplicationData('laravel', '10'),
        ];

        yield 'closure created server-side only' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                final class ClosureController
                {
                    public function run(Request $r)
                    {
                        $job = function (): string {
                            return 'ok';
                        };

                        return $job();
                    }
                }
                PHP,
            [],
            new ApplicationData('laravel', '10'),
        ];

        yield [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                final class TaskController
                {
                    public function run(Request $request)
                    {
                        $className = (string) $request->input('class');
                        $methodName = (string) $request->input('method');

                        $callable = [$className, $methodName];
                        return $callable();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_94,
                    "User-controlled callable from Request is invoked directly. Arbitrary code execution risk (CWE-94).
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    14,
                    Severity::HIGH->value,
                ),
            ],
            new ApplicationData('laravel', '10'),
        ];
    }
}
