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
use Obresoft\Racoony\Tests\LaravelRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(LaravelModelMassAssignmentRule::class)]
final class LaravelModelMassAssignmentRuleTest extends AbstractTestCase implements LaravelRule
{
    /**
     * @param list<Insight> $expected
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function test(string $code, array $expected, ?string $fileName = null): void
    {
        $this->runTest($code, $expected, $fileName ?? __FILE__);
    }

    /**
     * @return iterable<string, array{0: string, 1?: list<Insight>}>
     */
    public static function provideCases(): iterable
    {
        $fileName = '/app/Models/Posts/Post.php';

        yield 'missing fillable property' => [
            <<<'PHP'
                <?php

                namespace App\Models\Posts;

                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $guarded = [];
                }
                PHP,
            [
                new Vulnerability(
                    $fileName,
                    CWE::CWE_915,
                    'Model allows mass assignment: `$guarded = []` without a `$fillable` whitelist.
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    0,
                    Severity::HIGH->value,
                ),
            ],
            $fileName,
        ];

        yield 'guarded empty and fillable wildcard' => [
            <<<'PHP'
                <?php

                namespace App\Models\Posts;

                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $guarded = [];
                    protected $fillable = ['*'];
                }
                PHP,
            [
                new Vulnerability(
                    $fileName,
                    CWE::CWE_915,
                    'Model allows mass assignment: `$fillable` contains wildcard selection (`*` or `table.*`) enabling assignment of all attributes.
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    0,
                    Severity::HIGH->value,
                ),
            ],
            $fileName,
        ];

        yield 'fillable wildcard' => [
            <<<'PHP'
                <?php

                namespace App\Models\Posts;

                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $fillable = ['*'];
                }
                PHP,
            [
                new Vulnerability(
                    $fileName,
                    CWE::CWE_915,
                    'Model allows mass assignment: `$fillable` contains wildcard selection (`*` or `table.*`) enabling assignment of all attributes.
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    0,
                    Severity::HIGH->value,
                ),
            ],
            $fileName,
        ];

        yield 'fillable posts wildcard' => [
            <<<'PHP'
                <?php

                namespace App\Models\Posts;

                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $fillable = ['posts.*'];
                }
                PHP,
            [
                new Vulnerability(
                    $fileName,
                    CWE::CWE_915,
                    'Model allows mass assignment: `$fillable` contains wildcard selection (`*` or `table.*`) enabling assignment of all attributes.
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    0,
                    Severity::HIGH->value,
                ),
            ],
            $fileName,
        ];

        yield 'with fillable property for class' => [
            <<<'PHP'
                <?php

                namespace App\Models\Posts;

                use Illuminate\Database\Eloquent\Model as BaseModel;

                class Post extends BaseModel
                {
                    protected $fillable = ['name'];
                }
                PHP,
            [
            ],
            $fileName,
        ];

        yield 'guarded with wildcard protects all fields' => [
            <<<'PHP'
                <?php

                namespace App\Models\Posts;

                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $guarded = ['*'];
                }
                PHP,
            [
            ],
            $fileName,
        ];

        yield 'fillable and guarded both present' => [
            <<<'PHP'
                <?php

                namespace App\Models\Posts;

                use Illuminate\Database\Eloquent\Model;

                class Post extends Model
                {
                    protected $fillable = ['title'];
                    protected $guarded = ['is_admin'];
                }
                PHP,
            [
            ],
            $fileName,
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
            $fileName,
        ];
    }
}
