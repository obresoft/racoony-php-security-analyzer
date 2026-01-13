<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\CWE;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;
use PhpParser\Node;
use PhpParser\Node\Arg;

use function count;
use function in_array;
use function is_string;
use function sprintf;

/**
 * Scans for debug-related function calls such as var_dump, print_r, phpinfo, etc.
 *
 * CWE-215: Information Exposure Through Debug Information
 * @see https://cwe.mitre.org/data/definitions/215.html
 * Do not leave debug statements that could be executed in the source code.
 * Ensure that all debug information is eradicated before releasing the software.
 */
#[CWE('215', 'Information Exposure Through Debug Information', 'https://cwe.mitre.org/data/definitions/215.html')]
final class DebugFunctionExposureRule extends AbstractRule implements Rule
{
    /** @var list<string> */
    private array $debugFunctions = [
        'var_dump',
        'print_r',
        'var_export',
        'debug_print_backtrace',
        'debug_backtrace',
        'get_defined_vars',
        'get_defined_functions',
        'get_defined_constants',
        'phpinfo',
        'error_log',
        'trigger_error',
        'user_error',
        'dump',
        'dd',
        'ddump',
        'ddd',
        'console_log',
        'debug',
        'trace',
        'log_debug',
        'xdebug_debug_zval',
        'xdebug_var_dump',
        'xdebug_print_function_stack',
    ];

    /** @var list<string> */
    private array $debugMethods = ['dump', 'debug'];

    /** @var list<string> */
    private array $criticalFunctions = [
        'phpinfo',
        'get_defined_vars',
        'get_defined_functions',
        'get_defined_constants',
        'debug_backtrace',
    ];

    /**
     * @var list<string>
     */
    private array $sensitiveVariableNames = ['_session', 'database_config'];

    public function check(AnalysisContext $context): null|array|Insight
    {
        $node = $context->scope->node();
        if ($node instanceof Node\Expr\FuncCall) {
            $insights = $this->checkFunctionCall($node);
            if (null !== $insights) {
                return $insights;
            }
        }

        if ($node instanceof Node\Expr\MethodCall) {
            $insight = $this->checkMethodCall($node);
            if ($insight instanceof Insight) {
                return $insight;
            }
        }

        if ($node instanceof Node\Stmt\Echo_) {
            $insight = $this->checkEchoStatement($node);
            if ($insight instanceof Insight) {
                return $insight;
            }
        }

        return null;
    }

    private function checkFunctionCall(Node\Expr\FuncCall $node): null|array|Insight
    {
        if (!$node->name instanceof Node\Name) {
            return null;
        }

        $functionName = strtolower($node->name->toString());

        if (!in_array($functionName, $this->debugFunctions, true)) {
            return null;
        }

        $severity = in_array($functionName, $this->criticalFunctions, true) ? 'CRITICAL' : 'HIGH';
        $lineNumber = $node->getLine();

        $insights = [];

        $insights[] = $this->createInsight(
            'DEBUG_FUNCTION',
            sprintf('Debug function used: %s()', $functionName),
            $lineNumber,
            $severity,
        );

        if ('phpinfo' === $functionName) {
            $insights[] = $this->createInsight(
                'PHPINFO_USAGE',
                'CRITICAL: phpinfo() exposes full server configuration',
                $lineNumber,
                'CRITICAL',
            );
        }

        if (('var_dump' === $functionName || 'print_r' === $functionName) && isset($node->args[0])) {
            $firstArgument = $node->args[0];
            if ($firstArgument instanceof Arg) {
                $expr = $firstArgument->value;
                if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
                    $variableNameNormalized = strtolower($expr->name);
                    if (in_array($variableNameNormalized, $this->sensitiveVariableNames, true)) {
                        $insights[] = $this->createInsight(
                            'VARDUMP_SENSITIVE',
                            'var_dump/print_r may expose sensitive data: ',
                            $lineNumber,
                            'CRITICAL',
                        );
                    }
                }
            }
        }

        return 1 === count($insights) ? $insights[0] : $insights;
    }

    private function checkMethodCall(Node\Expr\MethodCall $node): ?Insight
    {
        if (!$node->name instanceof Node\Identifier) {
            return null;
        }

        $methodName = strtolower($node->name->toString());
        if (in_array($methodName, $this->debugMethods, true)) {
            return $this->createInsight(
                'DEBUG_METHOD',
                sprintf('Debug method call detected: ->%s()', $methodName),
                $node->getLine(),
            );
        }

        return null;
    }

    private function checkEchoStatement(Node\Stmt\Echo_ $node): ?Insight
    {
        foreach ($node->exprs as $expression) {
            if ($this->containsDebugInfo($expression)) {
                return $this->createInsight(
                    'DEBUG_ECHO',
                    'Echo statement with potential debug output detected',
                    $node->getLine(),
                );
            }
        }

        return null;
    }

    private function containsDebugInfo(Node $expression): bool
    {
        return $expression instanceof Node\Expr\FuncCall
            && $expression->name instanceof Node\Name
            && in_array(strtolower($expression->name->toString()), ['print_r', 'var_export'], true);
    }
}
