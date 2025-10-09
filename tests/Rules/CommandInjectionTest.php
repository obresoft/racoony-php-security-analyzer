<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Rules;

use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Rule\CWE\CommandInjectionRule;
use Obresoft\Racoony\Tests\AbstractTestCase;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Exception;

/**
 * @internal
 */
#[TestsRule(CommandInjectionRule::class)]
final class CommandInjectionTest extends AbstractTestCase
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
        yield 'shell_exec' => [
            <<<'PHP'
                <?php
                if (isset($_GET['ping'])) {
                    $host = $_GET['ping'];
                    $host .= ' ls';
                    $output = shell_exec("ping -c 3 $host");
                    echo $output;
                }
                ;
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function shell_exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    5,
                    'HIGH',
                ),
            ],
        ];

        yield 'json decode from php://input with error check' => [
            <<<'PHP'
                    <?php
                    $json = file_get_contents('php://input');
                    $data = json_decode($json, true);

                   exec($data['cmd']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection: raw input from php://input is used in a shell command via file_get_contents(). Sanitize and escape input properly before use.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'json decode from php://input from object' => [
            <<<'PHP'
                    <?php
                    $json = file_get_contents('php://input');
                    $data = json_decode($json);

                   exec($data->cmd);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection: raw input from php://input is used in a shell command via file_get_contents(). Sanitize and escape input properly before use.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'json decode from php://input from string' => [
            <<<'PHP'
                    <?php
                    $cmd = file_get_contents('php://input');

                   exec($cmd);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection: raw input from php://input is used in a shell command via file_get_contents(). Sanitize and escape input properly before use.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'json decode from php://stdin with command injection risk' => [
            <<<'PHP'
                <?php
                    $json = file_get_contents('php://stdin');
                    $data = json_decode($json, true);

                    if (json_last_error() !== JSON_ERROR_NONE) {
                        fwrite(STDERR, "Invalid JSON\n");
                        exit(1);
                    }

                    exec($data['cmd']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection: raw input from php://stdin is used in a shell command via file_get_contents(). Sanitize and escape input properly before use.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'exec with $_GET direct usage' => [
            <<<'PHP'
                <?php
                exec($_GET['cmd']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'system with $_POST direct usage' => [
            <<<'PHP'
                <?php
                system($_POST['command']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function system(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'shell_exec with $_REQUEST direct usage' => [
            <<<'PHP'
                <?php
                shell_exec($_REQUEST['shell_cmd']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function shell_exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'passthru with $_COOKIE direct usage' => [
            <<<'PHP'
                <?php
                passthru($_COOKIE['exec']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function passthru(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'popen with $_FILES usage (filename)' => [
            <<<'PHP'
                <?php
                popen($_FILES['file']['name'], 'r');
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function popen(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'popen with $_FILES usage' => [
            <<<'PHP'
                <?php
                popen($_FILES[0]['file']['name'], 'r');
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function popen(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'proc_open with variable from $_GET' => [
            <<<'PHP'
                <?php
                $cmd = $_GET['cmd'];
                proc_open($cmd, [], $pipes);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function proc_open(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        yield 'exec with safe hardcoded string' => [
            <<<'PHP'
                <?php
                exec('ls -la');
                PHP,
            [],
        ];

        yield 'exec with interpolated string with $_GET' => [
            <<<'PHP'
                <?php
                exec("ls {$_GET['param']}");
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'system with data from php://input (JSON)' => [
            <<<'PHP'
                <?php
                $json = file_get_contents('php://input');
                $data = json_decode($json, true);
                system($data['cmd']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection: raw input from php://input is used in a shell command via file_get_contents(). Sanitize and escape input properly before use.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'shell_exec with sanitized input' => [
            <<<'PHP'
                <?php
                $cmd = escapeshellcmd($_GET['cmd']);
                shell_exec($cmd);
                PHP,
            [],
        ];

        yield 'shell_exec without sanitized input' => [
            <<<'PHP'
                <?php
                $cmd = $_GET['cmd'];
                shell_exec($cmd);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function shell_exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        yield 'passthru with filtered numeric param' => [
            <<<'PHP'
                <?php
                $param = filter_var($_GET['param'], FILTER_VALIDATE_INT);
                if ($param !== false) {
                    passthru("ls -l $param");
                }
                PHP,
            [],
        ];

        yield 'proc_open with input from safe variable' => [
            <<<'PHP'
                <?php
                $safeCmd = 'ls -la';
                proc_open($safeCmd, [], $pipes);
                PHP,
            [],
        ];

        yield 'exec with concatenated user input and safe string' => [
            <<<'PHP'
                <?php
                $userInput = $_GET['filename'];
                $command = 'cat /var/log/' . $userInput;
                exec($command);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'system with sprintf formatting user input' => [
            <<<'PHP'
                <?php
                $cmd = sprintf('ping -c 1 %s', $_GET['host']);
                system($cmd);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function system(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        //        yield 'exec with user input through function parameter' => [
        //            <<<'PHP'
        //                <?php
        //                function runCommand($cmd) {
        //                    exec($cmd);
        //                }
        //                runCommand($_GET['command']);
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    'CWE-77',
        //                    "Potential command injection detected: user-controlled input (_GET line - 5) is used in shell command via the function exec(). Review input sanitization and use proper escaping.
        // [CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
        //                    3,
        //                    'HIGH',
        //                ),
        //            ],
        //        ];
        //
        //        yield 'exec with user input through function parameter and var' => [
        //            <<<'PHP'
        //                <?php
        //                function run($cmd) {
        //                    exec($cmd);
        //                }
        //
        //                $var = $_GET['command'];
        //                run($var);
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    'CWE-77',
        //                    "Potential command injection detected: user-controlled input (_GET line - 6) is used in shell command via the function exec(). Review input sanitization and use proper escaping.
        // [CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
        //                    3,
        //                    'HIGH',
        //                ),
        //            ],
        //        ];

        yield 'exec with user input through array access' => [
            <<<'PHP'
                <?php
                $commands = $_POST;
                exec($commands['cmd']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        yield 'shell_exec with nested user input access' => [
            <<<'PHP'
                <?php
                $data = json_decode($_POST['json'], true);
                shell_exec($data['commands']['primary']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function shell_exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        yield 'system with user input through ternary operator' => [
            <<<'PHP'
                <?php
                $cmd = isset($_GET['debug']) ? $_GET['debug'] : '';
                system($cmd);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function system(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    2,
                    'HIGH',
                ),
            ],
        ];

        yield 'exec with user input from session' => [
            <<<'PHP'
                <?php
                session_start();
                exec($_SESSION['stored_command']);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function exec(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        yield 'system with user input through file_get_contents from URL' => [
            <<<'PHP'
                <?php
                $cmd = file_get_contents($_GET['url']);
                system($cmd);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function system(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        yield 'passthru with user input through explode operation' => [
            <<<'PHP'
                <?php
                $parts = explode(' ', $_POST['command_line']);
                passthru($parts[0]);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function passthru(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    3,
                    'HIGH',
                ),
            ],
        ];

        yield 'system with user input through multiple assignments' => [
            <<<'PHP'
                <?php
                $a = $_GET['cmd'];
                $b = $a;
                $c = $b;
                system($c);
                PHP,
            [
                new Vulnerability(
                    __FILE__,
                    'CWE-77',
                    "Potential command injection detected: user-controlled input is used in shell command via the function system(). Review input sanitization and use proper escaping.
[CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
                    5,
                    'HIGH',
                ),
            ],
        ];

        //        yield 'exec with user input in heredoc syntax' => [
        //            <<<'PHP'
        //                <?php
        //                $command = <<<CMD
        //                ping -c 1 {$_GET['host']}
        //                CMD;
        //                exec($command);
        //                PHP,
        //            [
        //                new Vulnerability(
        //                    __FILE__,
        //                    'CWE-77',
        //                    "Potential command injection detected: user-controlled input (_GET line - 3) is used in shell command via the function exec(). Review input sanitization and use proper escaping.
        // [CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')] See: https://cwe.mitre.org/data/definitions/77.html",
        //                    5,
        //                    'HIGH',
        //                ),
        //            ],
        //        ];
    }
}
