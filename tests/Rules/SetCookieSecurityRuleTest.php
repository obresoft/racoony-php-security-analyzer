<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules;

use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\CWE\SetCookieSecurityRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(SetCookieSecurityRule::class)]
final class SetCookieSecurityRuleTest extends AbstractTestCase
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
        yield 'secure options with var' => [
            <<<'PHP'
                <?php
                $options = [
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Strict',
                ];

                setcookie('session_token', 'abc123', $options);
                PHP,
            [],
        ];

        yield 'missing secure flag (CWE-614)' => [
            <<<'PHP'
                <?php
                setcookie('token', 'abc123', [
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]);
                PHP,
            [
                new Vulnerability(__FILE__, 'SET_COOKIE_SECURE', "Missing `secure` flag in setcookie()\n[CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute] See: https://cwe.mitre.org/data/definitions/614.html", 2, Severity::HIGH->value),
            ],
        ];

        yield 'missing httponly flag (CWE-1004)' => [
            <<<'PHP'
                <?php
                setcookie('token', 'abc123', [
                    'secure' => true,
                    'samesite' => 'Strict'
                ]);
                PHP,
            [
                new Vulnerability(__FILE__, 'SET_COOKIE_HTTPONLY', "Missing `httponly` flag in setcookie()\n[CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag] See: https://cwe.mitre.org/data/definitions/1004.html", 2, Severity::HIGH->value),
            ],
        ];

        yield 'missing samesite flag (CWE-1275)' => [
            <<<'PHP'
                <?php
                setcookie('token', 'abc123', [
                    'secure' => true,
                    'httponly' => true
                ]);
                PHP,
            [
                new Vulnerability(__FILE__, 'SET_COOKIE_SAMESITE', "Missing or insecure `SameSite` flag in setcookie()\n[CWE-1275: Sensitive Cookie with Improper SameSite Attribute] See: https://cwe.mitre.org/data/definitions/1275.html", 2, Severity::MEDIUM->value),
            ],
        ];

        yield 'all missing (short setcookie)' => [
            <<<'PHP'
                <?php
                setcookie('token', 'abc123');
                PHP,
            [
                new Vulnerability(__FILE__, 'SET_COOKIE_SECURE', "setcookie() without secure options array
[CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute] See: https://cwe.mitre.org/data/definitions/614.html
[CWE-1275: Sensitive Cookie with Improper SameSite Attribute] See: https://cwe.mitre.org/data/definitions/1275.html
[CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag] See: https://cwe.mitre.org/data/definitions/1004.html", 2, Severity::HIGH->value, ),
            ],
        ];

        yield 'all secure attributes present' => [
            <<<'PHP'
                <?php
                setcookie('token', 'abc123', [
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]);
                PHP,
            [],
        ];
    }
}
