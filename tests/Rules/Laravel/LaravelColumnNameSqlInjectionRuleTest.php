<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelColumnNameSqlInjectionRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use Obresoft\Racoony\Tests\LaravelRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelColumnNameSqlInjectionRule::class)]
final class LaravelColumnNameSqlInjectionRuleTest extends AbstractTestCase implements LaravelRule
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
        yield 'orderByRaw-from-request' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                    public function index(Request $r) {
                        $orderExpr = (string) $r->query('sort');
                        return DB::table('users')->orderByRaw($orderExpr)->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'whereRaw-from-request' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                    public function index(Request $r) {
                        $whereRaw = (string) $r->query('get');
                        return DB::table('users')->whereRaw($whereRaw)->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'selectRaw-dynamic-column' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                   public function list(Request $r) {
                       $col = (string) $r->input('col');
                       return DB::table('users')->selectRaw("users.{$col} as value")->get();
                   }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'join-dynamic-table-and-column' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class ReportsController {
                   public function report(Request $r) {
                       $t = (string) $r->input('table');  // e.g. "admins"
                       $c = (string) $r->input('column'); // e.g. "is_super"
                       return DB::table('users')->join($t, 'users.id', '=', "{$t}.{$c}")->get();
                   }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    10,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    10,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'whereRaw-dynamic-identifier' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                   public function filter(Request $r) {
                       $col = (string) $r->query('by'); // e.g. "email"
                       $value = (string) $r->query('q');
                       return DB::table('users')->whereRaw("{$col} = ?", [$value])->get();
                   }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    10,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'groupByRaw-from-request' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                   public function grouped(Request $r) {
                       $by = (string) $r->input('group'); // e.g. "role"
                       return DB::table('users')->groupByRaw($by)->selectRaw('count(*) as c, '.$by)->get();
                   }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'table-name-from-request' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class AdminController {
                   public function debug(Request $r) {
                       $table = (string) $r->query('t'); // e.g. "users"
                       return DB::table($table)->limit(10)->get();
                   }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'eloquent-from-dynamic-table' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use App\Models\User;

                final class UsersController {
                   public function alt(Request $r) {
                       $table = (string) $r->input('t');
                       return User::query()->from($table)->get();
                   }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'orderByRaw-with-bindings' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                   public function tricky(Request $r) {
                       $expr = (string) $r->query('expr');
                       return DB::table('users')->orderByRaw('? ', [$expr])->get();
                   }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'whitelist-non-raw-orderBy' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                   public function index(Request $r) {
                       $allowed = ['id', 'email', 'created_at'];
                       $col = (string) $r->query('sort', 'id');
                       if (!in_array($col, $allowed, true)) {
                           $col = 'id';
                       }
                       return DB::table('users')->orderBy($col, 'asc')->get();
                   }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use App\Models\User;

                final class UsersController {
                   public function list(Request $r) {
                       $sort = (string) $r->query('sort', 'newest');
                       $map = ['newest' => 'created_at', 'name' => 'name', 'email' => 'email'];
                       $column = $map[$sort] ?? 'created_at';
                       return User::query()->orderBy($column)->get();
                   }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Support\Facades\DB;

                final class UsersController {
                   public function stable() {
                       return DB::table('users')->orderByRaw('created_at desc, id asc')->get();
                   }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class UsersController {
                   public function show(Request $r) {
                       $id = (int) $r->query('id', 1);
                       return DB::table('users')->select(['id','email'])->where('id', '=', $id)->get();
                   }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Support\Facades\DB;

                final class UsersController {
                    public function joined() {
                        return DB::table('users')->join('profiles', 'users.id', '=', 'profiles.user_id')->get();
                    }
                }
                PHP,
            [],
        ];

        yield 'havingRaw-user' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class ReportController {
                    public function agg(Request $r) {
                        $cond = (string) $r->input('having'); // user provided condition
                        return DB::table('orders')->selectRaw('status, COUNT(*) as c')->groupBy('status')->havingRaw($cond)->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class SafeExec {
                    public function run(Request $r) {
                        $id = (int) $r->input('id', 0);
                        $sql = <<< SQL
                        SELECT * FROM users WHERE id = :id and active = :active
                        SQL;

                        DB::select($sql, ['id' => $id, 'active' => $active]);
                    }
                }
                PHP,
            [],
        ];
    }
}
