<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules\Laravel;

use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\Laravel\LaravelSetCookieSecurityRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(LaravelSetCookieSecurityRule::class)]
final class LaravelSetCookieSecurityRuleTest extends AbstractTestCase
{
    /**
     * @param list<Insight> $expected
     * @throws Exception
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function test(string $code, array $expected): void
    {
        $this->runTest($code, $expected, 'config/session.php');
    }

    /**
     * @return iterable<string, array{0: string, 1?: list<Insight>}>
     */
    public static function provideCases(): iterable
    {
        yield 'all secure options set' => [
            <<<'PHP'
                <?php
                return [
                    'secure' => true,
                    'http_only' => true,
                    'same_site' => 'strict',
                ];
                PHP,
            [],
        ];

        yield 'missing secure flag' => [
            <<<'PHP'
                <?php
                return [
                    'http_only' => true,
                    'same_site' => 'lax',
                ];
                PHP,
            [
                new Vulnerability(
                    'config/session.php',
                    CWE::CWE_614,
                    "Missing `secure` flag in session cookie config
[CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute] See: https://cwe.mitre.org/data/definitions/614.html",
                    2,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'http_only flag false' => [
            <<<'PHP'
                <?php
                return [
                    'http_only' => false,
                    'same_site' => 'lax',
                     'secure' => true,
                ];
                PHP,
            [
                new Vulnerability(
                    'config/session.php',
                    CWE::CWE_1004,
                    "`http_only` should be `true` for secure cookies
[CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag] See: https://cwe.mitre.org/data/definitions/1004.html",
                    2,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'same_site flag  should be strict or lax' => [
            <<<'PHP'
                <?php
                return [
                    'http_only' => true,
                    'same_site' => 'none',
                    'secure' => true,
                ];
                PHP,
            [
                new Vulnerability(
                    'config/session.php',
                    CWE::CWE_1275,
                    '`same_site` should be `strict` or `lax`
[CWE-1275: Sensitive Cookie with Improper SameSite Attribute] See: https://cwe.mitre.org/data/definitions/1275.html',
                    2,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'missing http_only flag' => [
            <<<'PHP'
                <?php
                return [
                    'secure' => true,
                    'same_site' => 'lax',
                ];
                PHP,
            [
                new Vulnerability(
                    'config/session.php',
                    CWE::CWE_1004,
                    "Missing `http_only` flag in session cookie config
[CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag] See: https://cwe.mitre.org/data/definitions/1004.html",
                    2,
                    Severity::HIGH->value,
                ),
            ],
        ];

        yield 'missing same_site flag' => [
            <<<'PHP'
                <?php
                return [
                    'secure' => true,
                    'http_only' => true,
                ];
                PHP,
            [
                new Vulnerability(
                    'config/session.php',
                    CWE::CWE_1275,
                    'Missing or insecure `same_site` flag in session cookie config
[CWE-1275: Sensitive Cookie with Improper SameSite Attribute] See: https://cwe.mitre.org/data/definitions/1275.html',
                    2,
                    Severity::HIGH->value,
                ),
            ],
        ];
    }
}
