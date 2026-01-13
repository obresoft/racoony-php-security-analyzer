<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\PHP;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\PHP\UnserializeOnUntrustedDataRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(UnserializeOnUntrustedDataRule::class)]
final class UnserializeOnUntrustedDataRuleTest extends AbstractTestCase
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
        $expectedMessage = 'Do not call unserialize() on user-controlled data. This can lead to PHP Object Injection and potentially code execution depending on available gadget chains. Use JSON or a safe serialization format instead.
[CWE-502: Deserialization of Untrusted Data] See: https://cwe.mitre.org/data/definitions/502.html';

        yield 'reports $_GET variable' => [
            <<<'PHP'
                <?php
                $serializedPayloadFromUser = $_GET['data'];
                $restoredValue = unserialize($serializedPayloadFromUser);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    3,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'reports direct $_POST access' => [
            <<<'PHP'
                <?php
                $restoredValue = unserialize($_POST['payload']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    2,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'reports $_COOKIE value' => [
            <<<'PHP'
                <?php
                $serializedPayloadFromUser = $_COOKIE['session'];
                $restoredValue = unserialize($serializedPayloadFromUser);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    3,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'reports $_REQUEST value' => [
            <<<'PHP'
                <?php
                $serializedPayloadFromUser = $_REQUEST['data'];
                $restoredValue = unserialize($serializedPayloadFromUser);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    3,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'reports header value via $_SERVER' => [
            <<<'PHP'
                <?php
                $serializedPayloadFromUser = $_SERVER['HTTP_X_SERIALIZED'];
                $restoredValue = unserialize($serializedPayloadFromUser);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    3,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'reports tainted value flowing into function parameter' => [
            <<<'PHP'
                <?php
                function restoreFromSerializedPayload(string $serializedPayloadFromUser): mixed
                {
                    return unserialize($serializedPayloadFromUser);
                }

                $serializedPayloadFromUser = $_GET['data'];
                $restoredValue = restoreFromSerializedPayload($serializedPayloadFromUser);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    4,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'does not report json decode on user input' => [
            <<<'PHP'
                <?php
                $payloadFromUser = $_GET['data'];
                $decodedValue = json_decode($payloadFromUser, true, 512, JSON_THROW_ON_ERROR);
                PHP,
            [],
        ];

        yield 'does not report unserialize on hardcoded internal constant string' => [
            <<<'PHP'
                <?php
                $internalSerializedValue = 'a:1:{s:3:"foo";s:3:"bar";}';
                $restoredValue = unserialize($internalSerializedValue);
                PHP,
            [],
        ];

        yield 'reports two unserialize calls when both inputs are tainted' => [
            <<<'PHP'
                <?php
                $firstSerializedPayloadFromUser = $_GET['first'];
                $secondSerializedPayloadFromUser = $_POST['second'];

                $firstRestoredValue = unserialize($firstSerializedPayloadFromUser);
                $secondRestoredValue = unserialize($secondSerializedPayloadFromUser);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    5,
                    Severity::HIGH->value,
                ),
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    6,
                    Severity::HIGH->value,
                ),
            ],
        ];
    }

    /**
     * @param list<Insight> $expected
     * @throws Exception
     */
    #[Test]
    #[DataProvider('provideLaravelCases')]
    public function test_laravel(string $code, array $expected, ?ApplicationData $applicationData = null): void
    {
        $this->runTest($code, $expected, __FILE__, $applicationData);
    }

    /**
     * @return iterable<int|string, array{0: string, 1?: list<Insight>, 2?: ApplicationData}>
     */
    public static function provideLaravelCases(): iterable
    {
        $expectedMessage = 'Do not call unserialize() on user-controlled data. This can lead to PHP Object Injection and potentially code execution depending on available gadget chains. Use JSON or a safe serialization format instead.
[CWE-502: Deserialization of Untrusted Data] See: https://cwe.mitre.org/data/definitions/502.html';

        yield 'reports request()->input() value' => [
            <<<'PHP'
                <?php
                $serializedPayloadFromUser = request()->input('payload');
                $restoredValue = unserialize($serializedPayloadFromUser);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    3,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'reports $request->input() value' => [
            <<<'PHP'
                <?php
                declare(strict_types=1);

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $serializedPayloadFromUser = $request->input('payload');
                        $restoredValue = unserialize($serializedPayloadFromUser);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    15,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'reports request()->cookie() value' => [
            <<<'PHP'
                <?php
                declare(strict_types=1);

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                         $serializedPayloadFromUser = request()->cookie('cart');
                         $restoredValue = unserialize($serializedPayloadFromUser);
                    }
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_502,
                    $expectedMessage,
                    15,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'does not report json decode in Laravel controller' => [
            <<<'PHP'
                <?php
                declare(strict_types=1);

                namespace App\Http\Controllers;

                use Illuminate\Http\Request;
                use App\Http\Controllers\Controller;
                use App\Models\User;

                class UsersController extends Controller
                {
                    public function store(Request $request): void
                    {
                        $payloadFromUser = $request->all();
                        return json_decode($payloadFromUser, true, 512, JSON_THROW_ON_ERROR);
                    }
                }
                PHP,
            [],
        ];
    }
}
