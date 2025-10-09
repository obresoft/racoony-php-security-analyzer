<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules;

use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Recommendation;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\CWE\CodeInjectionRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(CodeInjectionRule::class)]
final class CodeInjectionRuleTest extends AbstractTestCase
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
     * @return iterable<string, array{0: string, 1?:list<Insight>}>
     */
    public static function provideCases(): iterable
    {
        yield 'eval code injection' => [
            <<<'PHP'
                <?php
                if (isset($_POST['code'])) {
                    $code = $_POST['code'];
                    eval($code);
                }
                ;
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-94',
                    "Potential code injection detected: user-controlled input code is used via the eval. Sanitize input properly before use.
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    4,
                    'HIGH',
                ),
            ],
        ];

        yield 'eval code injection $_GET direct usage ' => [
            <<<'PHP'
                <?php
                    eval($_GET['code']);
                ;
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-94',
                    "Potential code injection detected: user-controlled input _GET is used via the eval. Sanitize input properly before use.
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        //        yield 'eval code injection $_GET direct usage through function parameter' => [
        //            <<<'PHP'
        //                <?php
        //                function runCommand($cmd) {
        //                    eval($cmd);
        //                }
        //                runCommand($_GET['command']);
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    'CWE-94',
        //                    "Potential code injection detected: user-controlled input _GET is used via the eval. Sanitize input properly before use.
        // [CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
        //                    3,
        //                    'HIGH',
        //                ),
        //            ],
        //        ];

        yield 'include code injection' => [
            <<<'PHP'
                <?php
                include $_GET['file'];
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-94',
                    "Potential code injection detected: user-controlled input _GET is used via the include. Sanitize input properly before use.
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    2,
                    'HIGH',
                ),
            ],
        ];
        yield 'require code injection' => [
            <<<'PHP'
                <?php
                require $_POST['module'];
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-94',
                    "Potential code injection detected: user-controlled input _POST is used via the require. Sanitize input properly before use.
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'include_once code injection' => [
            <<<'PHP'
                <?php
                include_once $_REQUEST['lib'];
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-94',
                    "Potential code injection detected: user-controlled input _REQUEST is used via the include_once. Sanitize input properly before use.
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'indirect eval via variable' => [
            <<<'PHP'
                <?php
                $user_input = $_POST['code'];
                $code = "return " . $user_input . ";";
                eval($code);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-94',
                    "Potential code injection detected: user-controlled input _POST is used via the eval. Sanitize input properly before use.
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    4,
                    'HIGH',
                ),
            ],
        ];

        yield 'eval code injection common' => [
            <<<'PHP'
                <?php
                 eval('<?php');
                ;
                PHP,
            [
                new Recommendation(
                    __FILE__,
                    'CWE-94',
                    "Potential code injection detected: user-controlled via the eval. Sanitize input properly before use.
[CWE-94: Improper Control of Generation of Code ('Code Injection')] See: https://cwe.mitre.org/data/definitions/94.html",
                    2,
                ),
            ],
        ];
    }
}
