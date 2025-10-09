<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\CWE;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\InputAnalyzer;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

use function in_array;
use function sprintf;

/**
 * Scans for function calls such as exec, system, shell_exec, etc.
 *
 * CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
 * @see https://cwe.mitre.org/data/definitions/77.html
 * The product constructs all or part of a command using externally-influenced input from an upstream component,
 * but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when
 * it is sent to a downstream component.
 */
#[CWE('77', "Improper Neutralization of Special Elements used in a Command ('Command Injection')", 'https://cwe.mitre.org/data/definitions/77.html')]
final class CommandInjectionRule extends AbstractRule implements Rule
{
    /** @var array<string> */
    private const array SHELL_FUNCTIONS = [
        'exec',
        'system',
        'shell_exec',
        'passthru',
        'popen',
        'proc_open',
        'pcntl_exec',
    ];

    /** @var array<string> */
    private const array DANGEROUS_SHELL_CHARS = [';', '&', '|', '>', '<', '`', '$(', '${', '\\', '"', "'", '*', '?'];

    /** @var array<string> */
    private const array STREAMING_FUNCTIONS = ['file_get_contents'];

    /** @var array<string> */
    private const array STREAM_INPUT_SOURCE = ['php://input', 'php://stdin'];

    /** @var array<string> */
    private const array SAFE_FUNCTIONS = ['escapeshellcmd', 'filter_var'];

    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;

        if (!$scope->callAnalyzer()->isCallLike()) {
            return null;
        }

        if (!in_array($scope->callAnalyzer()->calleeName(), self::SHELL_FUNCTIONS, true)) {
            return null;
        }

        $inputAnalyzer = $context->analyzerResolver->get(InputAnalyzer::class);

        foreach ($scope->callAnalyzer()->argScopes() as $argScope) {
            if (($argScope->arrayAnalyzer()->isArrayDimFetch() || $argScope->isPropertyFetch()) && isset($argScope->node()->var)) {
                if ($inputAnalyzer->isUserInputExpr($argScope->node()->var)) {
                    return $this->report($scope->getLine(), $scope->callAnalyzer()->calleeName());
                }

                $argScope = $argScope->withNode($argScope->getRootVariable());
            }

            if ($argScope->isInterpolatedString()) {
                foreach ($argScope->interpolatedPartScopes() as $argValue) {
                    if ($inputAnalyzer->isUserInputExpr($argValue->node())) {
                        return $this->report($scope->getLine(), $scope->callAnalyzer()->calleeName());
                    }
                    $argScope = $argValue;
                }
            }

            if (!$argScope->isVariable()) {
                continue;
            }
            $calleeName = $scope->callAnalyzer()->calleeName();
            foreach ($context->scope->analyzeVariable($argScope->getVariableName()) as $data) {
                if ($data->scope->concatAnalyzer()->isConcat() || $data->scope->isTernary()) {
                    foreach ($data->meta as $fact) {
                        if ($inputAnalyzer->isUserInputExpr($fact->scope->node())) {
                            return $this->report($fact->scope->getLine(), $calleeName);
                        }
                    }
                }

                if (in_array($data->nameOrValue, self::SAFE_FUNCTIONS, true) && $data->scope->callAnalyzer()->isCallLike()) {
                    foreach ($data->scope->callAnalyzer()->argScopes() as $arg) {
                        if ($inputAnalyzer->isUserInputExpr($arg->node())) {
                            return null;
                        }
                    }
                }

                if ($inputAnalyzer->isUserInputExpr($data->scope->node())) {
                    return $this->report($scope->getLine(), $calleeName);
                }

                if (
                    $data->scope->callAnalyzer()->isCallLike() &&
                    in_array($data->scope->callAnalyzer()->calleeName(), self::STREAMING_FUNCTIONS, true) &&
                    $data->scope->callAnalyzer()->hasArgs() &&
                    in_array($data->scope->callAnalyzer()->firstArg()?->value ?? '', self::STREAM_INPUT_SOURCE, true)
                ) {
                    return $this->createInsight(
                        'CWE-77',
                        sprintf(
                            'Potential command injection: raw input from %s is used in a shell command via %s(). Sanitize and escape input properly before use.',
                            $data->scope->callAnalyzer()->firstArg()?->value ?? '',
                            $data->scope->callAnalyzer()->calleeName(),
                        ),
                        $data->scope->getLine(),
                        Severity::HIGH->value,
                    );
                }
            }
        }

        return null;
    }

    private function report(int $line, string $function): Insight
    {
        return $this->createInsight(
            'CWE-77',
            sprintf(
                'Potential command injection detected: user-controlled input is used in shell command via the function %s(). Review input sanitization and use proper escaping.',
                $function,
            ),
            $line,
            Severity::HIGH->value,
        );
    }
}
