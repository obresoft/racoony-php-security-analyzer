<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelMassAssignmentRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use Obresoft\Racoony\Tests\LaravelRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(LaravelMassAssignmentRule::class)]
final class LaravelMassAssignmentRuleTest extends AbstractTestCase implements LaravelRule
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
        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $validatedData = $request->validate([
                            'name' => 'required|string',
                            'email' => 'required|email',
                        ]);

                        User::where('id', 1)->update($validatedData);
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $validatedData = $request->validate([
                            'email' => 'required|email',
                            'name'  => 'required|string',
                        ]);
                        User::firstOrCreate(['email' => $validatedData['email']], ['name' => $validatedData['name']]);
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $validatedData = $request->validate([
                            'email' => 'required|email',
                            'name'  => 'required|string',
                        ]);
                        User::upsert([$validatedData], ['email'], ['name']);
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use App\Http\Controllers\Controller;
                use App\Models\User;
                use Illuminate\Foundation\Http\FormRequest;

                class StoreUserRequest extends FormRequest
                {
                    public function rules(): array
                    {
                        return [
                            'name'  => 'required|string',
                            'email' => 'required|email',
                        ];
                    }
                }

                class UsersController extends Controller
                {
                    public function store(StoreUserRequest $request): void
                    {
                        $data = $request->validated();
                        User::create($data);
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $request->validate([
                            'name'  => 'required|string',
                            'email' => 'required|email',
                            'role'  => 'nullable|string',
                        ]);

                        $whitelisted = $request->safe()->only(['name', 'email']);
                        User::create($whitelisted);
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $validatedData = $request->validate([
                            'name'  => 'required|string',
                            'email' => 'required|email',
                            'bio'   => 'nullable|string',
                        ]);

                        $attributes = [
                            'name'  => $validatedData['name'],
                            'email' => $validatedData['email'],
                            'bio'   => $validatedData['bio'] ?? null,
                        ];

                        User::where('id', 1)->update($attributes);
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                final class UserDto
                {
                    public function __construct(
                        public string $name,
                        public string $email,
                    ) {}

                    /** @param array{name:string,email:string} $data */
                    public static function fromValidatedArray(array $data): self
                    {
                        return new self($data['name'], $data['email']);
                    }

                    /** @return array{name:string,email:string} */
                    public function toArray(): array
                    {
                        return ['name' => $this->name, 'email' => $this->email];
                    }
                }

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $validated = $request->validate([
                            'name'  => 'required|string',
                            'email' => 'required|email',
                        ]);

                        $dto = UserDto::fromValidatedArray($validated);
                        User::create($dto->toArray());
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $validated = $request->validate([
                            'name'  => 'required|string',
                            'email' => 'required|email',
                            'bio'   => 'nullable|string',
                        ]);

                        $subset = [
                            'name'  => $validated['name'],
                            'email' => $validated['email'],
                        ];

                        User::where('id', 2)->update($subset);
                    }
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        User::update($request->all());
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        User::firstOrCreate($request->all());
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        User::upsert($request->all(), []);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    11,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        User::where('user_id', 1)->update($request->all());
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\Post;

                class UsersController extends Controller
                {
                    public function update(Request $request): void
                    {
                        POST::where('id', 1)->update($request->except(['_token']));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $user = User::find(2);
                        $user->posts()->create($request->all());
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    11,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        User::create(array_merge($request->all(), ['role' => 'user']));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function upsert(Request $request): void
                    {
                        User::updateOrCreate(['email' => request()->input('email')], $request->except(['_token']));
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(): void
                    {
                        User::upsert(request()->all(), ['email'], ['name','status']);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function update(Request $request): void
                    {
                        $user = User::find(1);
                        $user->fill($request->only(['name','email']))->save();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    11,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function update(Request $request): void
                    {
                        $user = User::find(1);
                        $user->forceFill($request->all())->save();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    11,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function update(Request $request): void
                    {
                        User::where('id', 1)->update($request->input());
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    10,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function update(Request $request): void
                    {
                        $user = User::find(1);
                        $user->forceFill($request->json()->all())->save();
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_915,
                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
[CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
                    11,
                    Severity::HIGH->value,
                ),
            ],
        ];

        //        yield [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function update(Request $request): void
        //                    {
        //                        $request->validate(['name' => 'required|string']);
        //                        User::where('id', 1)->update(['name' => $request->get('name')]);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //
        //
        //        yield 'Controller::store -> User::update($request->validated())' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validatedData = $request->validate([
        //                            'name' => 'required|string',
        //                            'email' => 'required|email',
        //                        ]);
        //
        //                        User::where('id', 1)->update($validatedData);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Controller::store -> User::firstOrCreate($request->validated())' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validatedData = $request->validate([
        //                            'email' => 'required|email',
        //                            'name'  => 'required|string',
        //                        ]);
        //                        User::firstOrCreate(['email' => $validatedData['email']], ['name' => $validatedData['name']]);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Controller::store -> User::upsert($request->validated(), [unique])' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validatedData = $request->validate([
        //                            'email' => 'required|email',
        //                            'name'  => 'required|string',
        //                        ]);
        //                        User::upsert([$validatedData], ['email'], ['name']);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Controller::store -> Using FormRequest::validated()' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                use Illuminate\Foundation\Http\FormRequest;
        //
        //                class StoreUserRequest extends FormRequest
        //                {
        //                    public function rules(): array
        //                    {
        //                        return [
        //                            'name'  => 'required|string',
        //                            'email' => 'required|email',
        //                        ];
        //                    }
        //                }
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(StoreUserRequest $request): void
        //                    {
        //                        $data = $request->validated();
        //                        User::create($data);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Controller::store -> $request->safe()->only([...]) after validation' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $request->validate([
        //                            'name'  => 'required|string',
        //                            'email' => 'required|email',
        //                            'role'  => 'nullable|string',
        //                        ]);
        //
        //                        $whitelisted = $request->safe()->only(['name', 'email']);
        //                        User::create($whitelisted);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Controller::store -> Explicit mapping, no raw $request->all()' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validatedData = $request->validate([
        //                            'name'  => 'required|string',
        //                            'email' => 'required|email',
        //                            'bio'   => 'nullable|string',
        //                        ]);
        //
        //                        $attributes = [
        //                            'name'  => $validatedData['name'],
        //                            'email' => $validatedData['email'],
        //                            'bio'   => $validatedData['bio'] ?? null,
        //                        ];
        //
        //                        User::where('id', 1)->update($attributes);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Controller::store -> DTO built from validated input' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                final class UserDto
        //                {
        //                    public function __construct(
        //                        public string $name,
        //                        public string $email,
        //                    ) {}
        //
        //                    /** @param array{name:string,email:string} $data */
        //                    public static function fromValidatedArray(array $data): self
        //                    {
        //                        return new self($data['name'], $data['email']);
        //                    }
        //
        //                    /** @return array{name:string,email:string} */
        //                    public function toArray(): array
        //                    {
        //                        return ['name' => $this->name, 'email' => $this->email];
        //                    }
        //                }
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validated = $request->validate([
        //                            'name'  => 'required|string',
        //                            'email' => 'required|email',
        //                        ]);
        //
        //                        $dto = UserDto::fromValidatedArray($validated);
        //                        User::create($dto->toArray());
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Controller::store -> Query builder update with validated subset' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validated = $request->validate([
        //                            'name'  => 'required|string',
        //                            'email' => 'required|email',
        //                            'bio'   => 'nullable|string',
        //                        ]);
        //
        //                        $subset = [
        //                            'name'  => $validated['name'],
        //                            'email' => $validated['email'],
        //                        ];
        //
        //                        User::where('id', 2)->update($subset);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'User::update($request->all())' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        User::update($request->all());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
        // [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
        //                    10,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Controller::store -> User::firstOrCreate($request->all())' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        User::firstOrCreate($request->all());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
        // [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
        //                    10,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Controller::store -> User::upsert($request->all(), [])' => [
        //            <<<'PHP'
        //                <?php
        //
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        User::upsert($request->all(), []);
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
        // [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
        //                    11,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Controller::store -> User::where(...)->update($request->all())' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        User::where('user_id', 1)->update($request->all());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).
        // [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes] See: https://cwe.mitre.org/data/definitions/915.html',
        //                    10,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        // ——— additional cases start ———
        //
        //        yield 'Relation::create($request->all()) on hasMany relation' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $user = User::find(1);
        //                        $user->posts()->create($request->all());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment via relation create(): user-controlled data passed from Request.',
        //                    11,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Model::fill($request->all())->save()' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function update(Request $request): void
        //                    {
        //                        $user = User::find(1);
        //                        $user->fill($request->all())->save();
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment via fill(): user-controlled data passed from Request.',
        //                    12,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Model::forceFill($request->all())->save()' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //
        //                class UsersController extends Controller
        //                {
        //                    public function update(Request $request): void
        //                    {
        //                        $user = User::find(1);
        //                        $user->forceFill($request->all())->save();
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Dangerous mass assignment via forceFill(): user-controlled data passed from Request.',
        //                    12,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Model::create(array_merge($request->all(), [...]))' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        User::create(array_merge($request->all(), ['role' => 'user']));
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Mass assignment via array_merge(Request::all(), ...).',
        //                    10,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'updateOrCreate($request->only([...])) safe subset' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function upsert(Request $request): void
        //                    {
        //                        $data = $request->only(['email', 'name']);
        //                        User::updateOrCreate(['email' => $data['email']], ['name' => $data['name']]);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'updateOrCreate($request->all()) unsafe' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function upsert(Request $request): void
        //                    {
        //                        User::updateOrCreate(['email' => 'a@b.c'], $request->all());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment in updateOrCreate(): user-controlled data passed.',
        //                    11,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Relation::createMany($request->all()) unsafe bulk' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function bulk(Request $request): void
        //                    {
        //                        $user = User::find(1);
        //                        $user->posts()->createMany($request->all());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment via relation createMany(): user-controlled data passed.',
        //                    12,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Query builder insert with sanitized array (safe)' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use Illuminate\Support\Facades\DB;
        //                use App\Http\Controllers\Controller;
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validated = $request->validate([
        //                            'name' => 'required|string',
        //                            'email' => 'required|email',
        //                        ]);
        //                        DB::table('users')->insert($validated);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Model::forceCreate($request->all()) unsafe' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        User::forceCreate($request->all());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Dangerous mass assignment via forceCreate(): user-controlled data passed.',
        //                    10,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Explicit mapping with defaults (safe)' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $validated = $request->validate([
        //                            'name' => 'required|string',
        //                            'email' => 'required|email',
        //                        ]);
        //                        $attributes = [
        //                            'name' => $validated['name'],
        //                            'email' => $validated['email'],
        //                            'role' => 'user',
        //                        ];
        //                        User::create($attributes);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'Nested: update($request->input()) unsafe generic' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function update(Request $request): void
        //                    {
        //                        User::where('id', 1)->update($request->input());
        //                    }
        //                }
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    CWE::CWE_915,
        //                    'Potential mass assignment via Request::input().',
        //                    10,
        //                    Severity::HIGH->value,
        //                ),
        //            ],
        //        ];
        //
        //        yield 'Validated + only([...]) chained (safe)' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function store(Request $request): void
        //                    {
        //                        $request->validate([
        //                            'name' => 'required|string',
        //                            'email' => 'required|email',
        //                            'ignored' => 'sometimes|string',
        //                        ]);
        //                        $safe = $request->only(['name', 'email']);
        //                        User::create($safe);
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
        //
        //        yield 'fill($request->only([...])) safe subset' => [
        //            <<<'PHP'
        //                <?php
        //                use Illuminate\Http\Request;
        //                use App\Http\Controllers\Controller;
        //                use App\Models\User;
        //                class UsersController extends Controller
        //                {
        //                    public function update(Request $request): void
        //                    {
        //                        $user = User::find(1);
        //                        $subset = $request->only(['name', 'email']);
        //                        $user->fill($subset);
        //                        $user->save();
        //                    }
        //                }
        //                PHP,
        //            [],
        //        ];
    }
}
