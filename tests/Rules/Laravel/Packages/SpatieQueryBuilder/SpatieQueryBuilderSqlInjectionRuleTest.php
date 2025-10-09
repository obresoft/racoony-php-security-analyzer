<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel\Packages\SpatieQueryBuilder;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\Packages\SpatieQueryBuilder\SpatieQueryBuilderSqlInjectionRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(SpatieQueryBuilderSqlInjectionRule::class)]
final class SpatieQueryBuilderSqlInjectionRuleTest extends AbstractTestCase
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

                use Spatie\QueryBuilder\QueryBuilder;
                use App\Models\User;

                final class UserIndexController {
                    public function __invoke() {
                        return QueryBuilder::for(User::class)
                            ->allowedSorts(request()->input('sort'))
                            ->get();
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

                use Spatie\QueryBuilder\QueryBuilder;
                use App\Models\Report;

                final class ReportController {
                    public function index() {
                        return QueryBuilder::for(Report::class)
                            ->defaultSort(request('order_by'))
                            ->get();
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

                use Spatie\QueryBuilder\QueryBuilder;
                use Spatie\QueryBuilder\AllowedSort;
                use App\Models\Customer;

                final class CustomerSortController {
                    public function list() {
                        return QueryBuilder::for(Customer::class)
                            ->allowedSorts([
                                AllowedSort::custom(request('sort'), new \App\Query\Sorts\CustomerScoreSort()),
                            ])
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    11,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use App\Models\Product;

                final class ProductController {
                    public function index() {
                        return QueryBuilder::for(Product::class)
                            ->allowedSorts(['name', 'price', 'created_at'])
                            ->get();
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use App\Models\Invoice;

                final class InvoiceReportController {
                    public function index() {
                        return QueryBuilder::for(Invoice::class)
                            ->defaultSort('created_at')
                            ->get();
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use Spatie\QueryBuilder\AllowedSort;
                use App\Models\Customer;

                final class CustomerSortControllerSafe {
                    public function list() {
                        return QueryBuilder::for(Customer::class)
                            ->allowedSorts([
                                AllowedSort::custom('score', new \App\Query\Sorts\CustomerScoreSort()),
                            ])
                            ->get();
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use Spatie\QueryBuilder\AllowedFilter;
                use App\Models\Customer;

                final class CustomerSortControllerUnsafe1 {
                    public function list() {
                        return QueryBuilder::for(Customer::class)
                            ->allowedFilters([
                                AllowedFilter::scope('complex', function ($query, $value) {
                                    $column = request('column');
                                    $query->where($column, $value);
                                }),
                            ])
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    13,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use Spatie\QueryBuilder\AllowedFilter;
                use App\Models\Customer;

                final class CustomerSortControllerUnsafe2 {
                    public function list() {
                        return QueryBuilder::for(Customer::class)
                            ->allowedFilters([
                                AllowedFilter::callback('search', function ($query, $value) {
                                    $query->whereRaw("name LIKE '%{$value}%'");
                                }),
                            ])
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_89,
                    "User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')] See: https://cwe.mitre.org/data/definitions/89.html",
                    12,
                    Severity::HIGH->value,
                ),
            ],
        ];
    }
}
