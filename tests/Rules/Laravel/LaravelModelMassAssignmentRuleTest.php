<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelModelMassAssignmentRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(LaravelModelMassAssignmentRule::class)]
final class LaravelModelMassAssignmentRuleTest extends AbstractTestCase
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
     * @return iterable<string, array{0: string, 1?: list<Insight>}>
     */
    public static function provideCases(): iterable
    {
        yield 'missing fillable property' => [
            <<<'PHP'
                <?php

                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $guarded = [];
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Model allows mass assignment: `$guarded = []` without a `$fillable` whitelist.
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    0,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'with fillable property for class' => [
            <<<'PHP'
                <?php
                use Illuminate\Database\Eloquent\Model as BaseModel;

                class Post extends BaseModel
                {
                    protected $fillable = ['name'];
                }
                PHP,
            [
            ],
        ];

        yield 'guarded with wildcard protects all fields' => [
            <<<'PHP'
                <?php
                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $guarded = ['*'];
                }
                PHP,
            [
            ],
        ];

        yield 'fillable and guarded both present' => [
            <<<'PHP'
                <?php
                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $fillable = ['title'];
                    protected $guarded = ['is_admin'];
                }
                PHP,
            [
            ],
        ];

        yield 'no fillable or guarded defined' => [
            <<<'PHP'
                <?php
                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                }
                PHP,
            [
            ],
        ];
    }
}
