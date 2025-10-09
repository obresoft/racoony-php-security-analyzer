<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel\Packages\SpatieQueryBuilder;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\Packages\SpatieQueryBuilder\SpatieQueryBuilderAuthorizationBypassRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(SpatieQueryBuilderAuthorizationBypassRule::class)]
final class SpatieQueryBuilderAuthorizationBypassRuleTest extends AbstractTestCase
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
                use App\Models\Post;

                final class PostIncludeController {
                    public function index() {
                        return QueryBuilder::for(Post::class)
                            ->allowedIncludes(request('include'))
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_639,
                    'User-controlled include/fieldset may bypass authorization. An attacker can request unauthorized relations or fields.
[CWE-639: Authorization Bypass Through User-Controlled Key] See: https://cwe.mitre.org/data/definitions/639.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use App\Models\Account;

                final class AccountFieldsController {
                    public function show() {
                        return QueryBuilder::for(Account::class)
                            ->allowedFields($_GET['fields'])
                            ->get();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_639,
                    'User-controlled include/fieldset may bypass authorization. An attacker can request unauthorized relations or fields.
[CWE-639: Authorization Bypass Through User-Controlled Key] See: https://cwe.mitre.org/data/definitions/639.html',
                    9,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'allowedIncludes literal (safe)' => [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use App\Models\Blog;

                final class BlogIncludeController {
                    public function list() {
                        return QueryBuilder::for(Blog::class)
                            ->allowedIncludes(['author', 'comments'])
                            ->get();
                    }
                }
                PHP,
            [],
        ];

        yield 'allowedFields literal (safe)' => [
            <<<'PHP'
                <?php

                use Spatie\QueryBuilder\QueryBuilder;
                use App\Models\Account;

                final class AccountFieldsetController {
                    public function show() {
                        return QueryBuilder::for(Account::class)
                            ->allowedFields(['id', 'name', 'email'])
                            ->get();
                    }
                }
                PHP,
            [],
        ];
    }
}
