<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelOpenRedirectRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelOpenRedirectRule::class)]
final class LaravelOpenRedirectRuleTest extends AbstractTestCase
{
    /**
     * @param list<Insight> $expected
     * @throws Exception
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function test(string $code, array $expected): void
    {
        $this->runTest($code, $expected, __FILE__);
    }

    /**
     * @return iterable<int|string, array{0: string, 1?: list<Insight>}>
     */
    public static function provideCases(): iterable
    {
        yield 'unsafe redirect with input()' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index(Request $request)
                    {
                        return redirect()->to($request->input('path'));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with input() with namespace' => [
            <<<'PHP'
                <?php

                declare(strict_types=1);

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index(Request $request)
                    {
                        return redirect()->to($request->input('path'));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    13,
                    Severity::HIGH->value,
                ),
            ],
        ];

        //        yield 'unsafe redirect with query() and concatenation' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //                use Illuminate\Routing\Redirector;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        return (new Redirector(url()))->away('/somewhere/' . $request->query('path'));
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];

        yield 'unsafe redirect with post()' => [
            <<<'PHP'
                <?php

                use Illuminate\Support\Facades\Redirect;

                class RedirectController
                {
                    public function index()
                    {
                        return Redirect::to(request()->post('path'));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with get() method' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index(Request $request)
                    {
                        return redirect()->to($request->get('url'));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with superglobal $_GET' => [
            <<<'PHP'
                <?php

                class RedirectController
                {
                    public function index()
                    {
                        return redirect()->to($_GET['redirect_to']);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    7,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with superglobal $_POST' => [
            <<<'PHP'
                <?php

                use Illuminate\Support\Facades\Redirect;

                class RedirectController
                {
                    public function index()
                    {
                        return Redirect::away($_POST['next']);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        //        yield 'unsafe redirect with superglobal $_REQUEST' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->route('home', ['url' => $_REQUEST['goto']]);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];

        yield 'unsafe redirect with cookie input' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index()
                    {
                        $request = new Request();
                        return redirect()->to($request->cookie('link'));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with cookie input as var' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index()
                    {
                        $request = (new Request())->get('link');
                        return redirect()->to($request);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with cookie input two methods' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index()
                    {
                        $request = new Request();
                        return redirect()->to($request->cookie('link'));
                    }

                    public function view()
                    {
                        $request = [];
                        return redirect()->secure($request);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with cookie input as param' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index(Request $request)
                    {
                        return redirect()->away($request->cookie('link'));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index(Request $request)
                    {
                        return redirect()->route($request->cookie('link'));
                    }
                }
                PHP,
            [
            ],
        ];

        yield 'unsafe redirect with header input' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index(Request $request)
                    {
                        $referrer = $request->header('link');

                        return redirect()->away($referrer);
                    }


                    public function view(Request $request)
                    {
                        $data = (new Test())->get();

                        return new JsonResponse($data);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    11,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'unsafe redirect with json input' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;

                class RedirectController
                {
                    public function index(Request $request)
                    {
                        $data = $request->json('redirect_url');
                        return redirect()->to($data);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_601,
                    'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.
[CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        //        yield 'unsafe redirect with request() helper' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->to(request('next_page'));
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with variable assignment' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        $path = $request->input('path');
        //                        return redirect()->to($path);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with multiple method chaining' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        return redirect()
        //                            ->to($request->input('redirect'))
        //                            ->with('success', 'Redirected!');
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with route method' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        return redirect()->route($request->input('route_name'));
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with action method' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        return redirect()->action($request->input('controller'));
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with all() method' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        $data = $request->all();
        //                        return redirect()->to($data['redirect_to']);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with only() method' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        $fields = $request->only(['redirect_url']);
        //                        return redirect()->away($fields['redirect_url']);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with except() method' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        $data = $request->except(['_token']);
        //                        return redirect()->to($data['next']);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with server() method' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        $referer = $request->server('HTTP_REFERER');
        //                        return redirect()->to($referer);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with $_COOKIE superglobal' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->to($_COOKIE['return_url']);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with $_SESSION superglobal' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->to($_SESSION['intended_url']);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'safe redirect to fixed internal path' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->to('/dashboard');
        //                    }
        //                }
        //                PHP,
        //            [
        //            ],
        //        ];
        //
        //        yield 'safe redirect to route with fixed name' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->route('user.profile');
        //                    }
        //                }
        //                PHP,
        //            [
        //            ],
        //        ];
        //
        //        yield 'safe redirect back' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->back();
        //                    }
        //                }
        //                PHP,
        //            [
        //            ],
        //        ];
        //
        //        yield 'safe redirect with hardcoded URL' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Support\Facades\Redirect;
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return Redirect::away('https://example.com');
        //                    }
        //                }
        //                PHP,
        //            [
        //            ],
        //        ];
        //
        //        yield 'safe redirect with config value' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function go()
        //                    {
        //                        return redirect()->to(config('app.home_url'));
        //                    }
        //                }
        //                PHP,
        //            [
        //            ],
        //        ];
        //
        //        yield 'safe redirect with env value' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->to(env('DEFAULT_REDIRECT_URL', '/dashboard'));
        //                    }
        //                }
        //                PHP,
        //            [
        //            ],
        //        ];
        //
        //        yield 'safe redirect with url() helper' => [
        //            <<<'PHP'
        //                <?php
        //
        //                class RedirectController
        //                {
        //                    public function index()
        //                    {
        //                        return redirect()->to(url('/users'));
        //                    }
        //                }
        //                PHP,
        //            [
        //            ],
        //        ];
        //
        //        yield 'complex unsafe redirect with multiple user inputs in concatenation' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        $base = $request->input('base_url');
        //                        $path = $request->query('path');
        //                        return redirect()->to($base . '/' . $path);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'unsafe redirect with ternary operator' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //
        //                class RedirectController
        //                {
        //                    public function index(Request $request)
        //                    {
        //                        $url = $request->input('redirect_url') ?: '/default';
        //                        return redirect()->to($url);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_601,
        //                    'Possible Open Redirect: redirect destination is based on user input. Validate or whitelist allowed URLs.
        // [CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')] See: https://cwe.mitre.org/data/definitions/601.html',
        //                    0,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
    }
}
