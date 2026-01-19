<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelModelHiddenFieldsLeakageOnDbSelectRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use Obresoft\Racoony\Tests\LaravelRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(LaravelModelHiddenFieldsLeakageOnDbSelectRule::class)]
final class LaravelModelHiddenFieldsLeakageOnDbSelectRuleTest extends AbstractTestCase implements LaravelRule
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
     * @return iterable<int|string, array{0: string, 1?: list<Vulnerability>}>
     */
    public static function provideCases(): iterable
    {
        yield 'model_with_empty_hidden_attributes_should_not_report' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use App\Http\Controllers\Controller;

                class UsersController extends Controller
                {
                    public function index(): void
                    {
                        return \DB::table('user_profiles as u')
                            ->select(['id', 'user_id', 'first_name', 'last_name'])
                            ->get();
                    }
                }
                PHP,
            [],
        ];

        yield 'users_select_wildcard_alias_star_should_report' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use App\Http\Controllers\Controller;

                class UsersController extends Controller
                {
                    public function index(): void
                    {
                        return \DB::table('users as u')
                            ->select('u.*')
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [password, remember_token] from table "users".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    11,
                    Severity::MEDIUM->value,
                ),
            ],
        ];

        yield 'users_select_hidden_fields_via_variable_should_report' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use App\Http\Controllers\Controller;

                class UsersController extends Controller
                {
                    public function index(): void
                    {
                        $selectFields = ['id', 'password'];

                        return \DB::table('users as u')
                            ->select($selectFields)
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [password] from table "users".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    13,
                    Severity::MEDIUM->value,
                ),
            ],
        ];

        yield 'users_select_hidden_field_explicit_should_report' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use App\Http\Controllers\Controller;
                use Illuminate\Support\Facades\DB;

                class UsersController extends Controller
                {
                    public function index(): void
                    {
                        return DB::table('users as u')
                            ->select([
                                'u.password',
                                'u.id',
                            ])
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [password] from table "users".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    12,
                    Severity::MEDIUM->value,
                ),
            ],
        ];

        yield 'non_users_table_should_not_report' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use App\Http\Controllers\Controller;

                class UserProfilesController extends Controller
                {
                    public function index(): void
                    {
                        $selectFields = ['id', 'user_id', 'first_name', 'last_name'];

                        return \DB::table('user_profiles as up')
                            ->select($selectFields)
                            ->get();
                    }
                }
                PHP,
            [],
        ];

        yield 'composed_query_variable_select_then_get_wildcard_should_report' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use App\Http\Controllers\Controller;

                class UsersController extends Controller
                {
                    public function index(): void
                    {
                        $query = \DB::table('users as u');

                        $query = $query->select('u.*');

                        $query->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [password, remember_token] from table "users".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    13,
                    Severity::MEDIUM->value,
                ),
            ],
        ];

        yield 'users_without_select_should_report' => [
            <<<'PHP'
                <?php
                class UsersController {
                    public function index() {
                        return \DB::table('users')->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [password, remember_token] from table "users".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    4,
                    Severity::MEDIUM->value,
                ),
            ],
        ];

        yield 'users_without_select_should_report_firstOrFail' => [
            <<<'PHP'
                <?php
                class UsersController {
                    public function index() {
                        return \DB::table('users')->findOrFail();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [password, remember_token] from table "users".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    4,
                    Severity::MEDIUM->value,
                ),
            ],
        ];

        yield 'db_value_non_hidden_column_should_be_safe' => [
            <<<'PHP'
                <?php

                namespace App;

                use Illuminate\Support\Facades\DB;

                final class Example
                {
                    public function run(): void
                    {
                        DB::table('users')->where('id', 1)->value('name');
                    }
                }
                PHP,
            [],
        ];

        yield 'db_value_hidden_column_should_report' => [
            <<<'PHP'
                <?php

                use Illuminate\Support\Facades\DB;

                final class Example
                {
                    public function run(): void
                    {
                        DB::table('users')->where('id', 1)->value('password');
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [password] from table "users".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    9,
                    Severity::MEDIUM->value,
                ),
            ],
        ];

        yield 'user_profile_select_read_from_class_attribute' => [
            <<<'PHP'
                <?php

                namespace App\Http\Controllers;

                use App\Http\Controllers\Controller;

                class UsersController extends Controller
                {
                    public function index(): void
                    {
                        return \DB::table('user_contacts as u')
                            ->select('u.*')
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_201,
                    'Hidden fields leakage detected: selecting hidden attribute(s) [email, first_name] from table "user_contacts".
[CWE-201: Insertion of Sensitive Information Into Sent Data] See: https://cwe.mitre.org/data/definitions/201.html',
                    11,
                    Severity::MEDIUM->value,
                ),
            ],
        ];
    }
}
