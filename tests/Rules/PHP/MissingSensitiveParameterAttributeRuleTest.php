<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\PHP;

use Exception;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\PHP\MissingSensitiveParameterAttributeRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
#[TestsRule(MissingSensitiveParameterAttributeRule::class)]
final class MissingSensitiveParameterAttributeRuleTest extends AbstractTestCase
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
                function login(string $password, string $email): void {}
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_532,
                    'Parameter $password may hold sensitive data but is missing #[\SensitiveParameter] attribute. Consider adding it.
[CWE-532: Insertion of Sensitive Information into Log File.] See: https://cwe.mitre.org/data/definitions/532.html',
                    2,
                    Severity::LOW->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                function login(#[\SensitiveParameter] string $password, string $email): void {}
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                final class AuthController {
                    public function setToken(string $apiToken): void {}
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_532,
                    'Parameter $apiToken may hold sensitive data but is missing #[\SensitiveParameter] attribute. Consider adding it.
[CWE-532: Insertion of Sensitive Information into Log File.] See: https://cwe.mitre.org/data/definitions/532.html',
                    3,
                    Severity::LOW->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                final class PaymentService {
                    public function charge(string $creditCard, int $amount): void {}
                }
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_532,
                    'Parameter $creditCard may hold sensitive data but is missing #[\SensitiveParameter] attribute. Consider adding it.
[CWE-532: Insertion of Sensitive Information into Log File.] See: https://cwe.mitre.org/data/definitions/532.html',
                    3,
                    Severity::LOW->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                final class UserController {
                    public function updateEmail(string $email): void {}
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                $handler = function (string $secret): void {};
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_532,
                    'Parameter $secret may hold sensitive data but is missing #[\SensitiveParameter] attribute. Consider adding it.
[CWE-532: Insertion of Sensitive Information into Log File.] See: https://cwe.mitre.org/data/definitions/532.html',
                    2,
                    Severity::LOW->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                function rotate(#[\SensitiveParameter] string $token): void {}
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                #[\Deprecated]
                function legacy(string $secret): void {}
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    CWE::CWE_532,
                    'Parameter $secret may hold sensitive data but is missing #[\SensitiveParameter] attribute. Consider adding it.
[CWE-532: Insertion of Sensitive Information into Log File.] See: https://cwe.mitre.org/data/definitions/532.html',
                    3,
                    Severity::LOW->value,
                ),
            ],
        ];

        yield [
            <<<'PHP'
                <?php
                use SensitiveParameter;

                #[\Deprecated]
                function legacy(#[SensitiveParameter] string $secret): void {}
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                namespace App;
                use SensitiveParameter;
                final class A {
                    public function foo(#[SensitiveParameter] string $password): void {}
                }
                PHP,
            [],
        ];

        yield [
            <<<'PHP'
                <?php
                namespace App;
                final class A {
                    public function foo($accounting): void {}
                }
                PHP,
            [],
        ];
    }
}
