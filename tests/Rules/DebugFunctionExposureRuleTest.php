<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules;

use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\CWE\DebugFunctionExposureRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(DebugFunctionExposureRule::class)]
final class DebugFunctionExposureRuleTest extends AbstractTestCase
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
        yield 'simple var_dump' => [
            '<?php var_dump($a);',
            [
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', "Debug function used: var_dump()\n[CWE-215: Information Exposure Through Debug Information] See: https://cwe.mitre.org/data/definitions/215.html", 1, 'HIGH'),
            ],
        ];
        yield 'phpinfo critical function' => [
            '<?php phpinfo();',
            [
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', "Debug function used: phpinfo()\n[CWE-215: Information Exposure Through Debug Information] See: https://cwe.mitre.org/data/definitions/215.html", 1, 'CRITICAL'),
                new Vulnerability(__FILE__, 'PHPINFO_USAGE', "CRITICAL: phpinfo() exposes full server configuration\n[CWE-215: Information Exposure Through Debug Information] See: https://cwe.mitre.org/data/definitions/215.html", 1, 'CRITICAL'),
            ],
        ];

        yield 'print_r with session variable' => [
            '<?php print_r($_SESSION);',
            [
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', "Debug function used: print_r()\n[CWE-215: Information Exposure Through Debug Information] See: https://cwe.mitre.org/data/definitions/215.html", 1, 'HIGH'),
                new Vulnerability(__FILE__, 'VARDUMP_SENSITIVE', "var_dump/print_r may expose sensitive data: \n[CWE-215: Information Exposure Through Debug Information] See: https://cwe.mitre.org/data/definitions/215.html", 1, 'CRITICAL'),
            ],
        ];

        yield 'method call debug()' => [
            '<?php $logger->debug("sensitive data");',
            [
                new Vulnerability(__FILE__, 'DEBUG_METHOD', "Debug method call detected: ->debug()\n[CWE-215: Information Exposure Through Debug Information] See: https://cwe.mitre.org/data/definitions/215.html", 1, 'MEDIUM'),
            ],
        ];
        $prefix = "\n[CWE-215: Information Exposure Through Debug Information] See: https://cwe.mitre.org/data/definitions/215.html";
        yield 'multiple debug calls' => [
            <<<'PHP'
                <?php

                phpinfo();
                var_dump($_SESSION);
                print_r($database_config);
                debug_backtrace();


                var_dump($user_data);
                print_r($response);
                var_export($array, true);
                debug_print_backtrace();

                if ($debug) {
                    var_dump($data);
                }


                $object->dump();
                $collection->toArray();


                echo print_r($data, true);

                dump($variable);
                dd($data);


                error_log(print_r($data, true));


                xdebug_var_dump($data);
                PHP,
            [
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: phpinfo()' . $prefix, 3, 'CRITICAL'),
                new Vulnerability(__FILE__, 'PHPINFO_USAGE', 'CRITICAL: phpinfo() exposes full server configuration' . $prefix, 3, 'CRITICAL'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: var_dump()' . $prefix, 4, 'HIGH'),
                new Vulnerability(__FILE__, 'VARDUMP_SENSITIVE', 'var_dump/print_r may expose sensitive data: ' . $prefix, 4, 'CRITICAL'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: print_r()' . $prefix, 5, 'HIGH'),
                new Vulnerability(__FILE__, 'VARDUMP_SENSITIVE', 'var_dump/print_r may expose sensitive data: ' . $prefix, 5, 'CRITICAL'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: debug_backtrace()' . $prefix, 6, 'CRITICAL'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: var_dump()' . $prefix, 9, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: print_r()' . $prefix, 10, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: var_export()' . $prefix, 11, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: debug_print_backtrace()' . $prefix, 12, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: var_dump()' . $prefix, 15, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_METHOD', 'Debug method call detected: ->dump()' . $prefix, 19, 'MEDIUM'),
                new Vulnerability(__FILE__, 'DEBUG_ECHO', 'Echo statement with potential debug output detected' . $prefix, 23, 'MEDIUM'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: print_r()' . $prefix, 23, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: dump()' . $prefix, 25, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: dd()' . $prefix, 26, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: error_log()' . $prefix, 29, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: print_r()' . $prefix, 29, 'HIGH'),
                new Vulnerability(__FILE__, 'DEBUG_FUNCTION', 'Debug function used: xdebug_var_dump()' . $prefix, 32, 'HIGH'),
            ],
        ];

        yield 'safe code' => [
            '<?php echo "safe";',
            [],
        ];
    }
}
