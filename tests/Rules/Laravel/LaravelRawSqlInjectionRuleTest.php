<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use App\Models\User;
use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelRawSqlInjectionRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelRawSqlInjectionRule::class)]
final class LaravelRawSqlInjectionRuleTest extends AbstractTestCase
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

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class SearchController {
                    public function search(Request $r) {
                        $term = (string) $r->input('q');
                        return DB::select("SELECT * FROM users WHERE name LIKE '%{$term}%'");
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

                final class AdminController {
                    public function drop(Request $r) {
                        $table = (string) $r->input('table');
                        DB::statement('DROP TABLE ' . $table);
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

        yield 'db-statement-user-fragment-with-bindings' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class ExecController {
                    public function run(Request $r) {
                        $frag = (string) $r->input('frag'); // e.g. "status = 'active' OR 1=1"
                        $id = (int) $r->input('id', 0);
                        DB::statement("UPDATE users SET {$frag} WHERE id = ?", [$id]);
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
            ],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class ImportController {
                    public function import(Request $r) {
                        $selectFragment = (string) $r->input('sel'); // user controlled SELECT fragment
                        DB::table('archive')->insertUsing(['name','meta'], DB::raw("SELECT name, {$selectFragment} FROM users"));
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

                final class UpdateController {
                    public function bump(Request $r) {
                        $inc = (string) $r->input('inc'); // e.g. "amount + 10, name = 'hacked'"
                        DB::table('wallets')->where('id', 1)->update(['balance' => DB::raw($inc)]);
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

                final class UnionController {
                    public function union(Request $r) {
                        $frag = (string) $r->input('u');
                        $q1 = DB::table('a')->select('id');
                        $q2 = DB::table('b')->select(DB::raw($frag));
                        return $q1->union(DB::query()->fromSub($q2, 'sub'))->get();
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
            ],
        ];

        yield 'db-select-parameterized-safe' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class SafeController {
                    public function get(Request $r) {
                        $q = (string) $r->input('q', '');
                        return DB::select('SELECT * FROM users WHERE name LIKE ?', ['%'.$q.'%']);
                    }
                }
                PHP,
            [],
        ];

        yield 'db-statement-fixed-with-bindings-safe' => [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class SafeExec {
                    public function run(Request $r) {
                        $id = (int) $r->input('id', 0);
                        DB::statement('UPDATE users SET active = ? WHERE id = ?', [1, $id]);
                    }
                }
                PHP,
            [],
        ];

        //        yield 'nested-whereRaw-and-dbraw' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //                use Illuminate\Support\Facades\DB;
        //
        //                final class MixedController {
        //                    public function complex(Request $r) {
        //                        $frag = (string) $r->input('frag');
        //                        return DB::table('items')->where(function ($q) use ($frag, $r) {
        //                            $q->whereRaw($frag);
        //                            $q->where('active', DB::raw((string) $r->input('active')));
        //                        })->get();
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_89,
        //                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
        // [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
        //                    9,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use Illuminate\Support\Facades\DB;

                final class SafeExec {
                    public function run(Request $r) {
                        $id = $request->get('id');
                        $active= $request->get('active');
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
