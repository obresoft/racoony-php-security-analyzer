<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRequestCallAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;
use PhpParser\Node;
use PhpParser\Node\Expr\Variable;

use function in_array;

#[CWE('94', "Improper Control of Generation of Code ('Code Injection')", 'https://cwe.mitre.org/data/definitions/94.html')]
final class LaravelInsecureCallableFromRequest extends AbstractRule implements Rule
{
    private const string MESSAGE = 'User-controlled callable from Request is invoked directly. Arbitrary code execution risk (CWE-94).';

    private const array CALL_LIKE_FUNCTIONS = [
        'call_user_func',
        'call_user_func_array',
        'forward_static_call',
        'forward_static_call_array',
    ];

    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;

        if (!$scope->callAnalyzer()->isCallLike()) {
            return null;
        }

        $inputAnalyzer = $context->analyzerResolver->get(LaravelRequestCallAnalyzer::class);
        $nodeValueScope = isset($scope->node()->name) && $scope->node()->name instanceof Node
            ? $scope->withNode($scope->node()->name)
            : null;

        if (null !== $nodeValueScope && $nodeValueScope->isVariable()) {
            return $this->detectVulnerability($nodeValueScope, $nodeValueScope->nameAsString(), $inputAnalyzer);
        }

        $functionName = $scope->callAnalyzer()->calleeName() ?? '';

        if (in_array($functionName, self::CALL_LIKE_FUNCTIONS, true)) {
            foreach ($scope->callAnalyzer()->argScopes() as $argScope) {
                $variableName = $argScope->nameAsString() ?? '';
                if ($argScope->arrayAnalyzer()->isArray()) {
                    $argScope = $scope->withNode($argScope->arrayAnalyzer()->getFirstArrayItem());
                    $variableName = isset($argScope->node()->value) && $argScope->node()->value instanceof Variable
                        ? $argScope->node()->value->name
                        : '';
                }

                return $this->detectVulnerability($argScope, $variableName, $inputAnalyzer);
            }
        }

        return $this->detectVulnerability($scope, $functionName, $inputAnalyzer);
    }

    private function detectVulnerability(Scope $scope, string $varName, LaravelRequestCallAnalyzer $inputAnalyzer): ?Insight
    {
        $var = $scope->analyzeVariable($varName);

        foreach ($var as $varValue) {
            $variableScope = $varValue->scope;
            if ($variableScope->callAnalyzer()->isMethodCall()) {
                if ($inputAnalyzer->withScope($variableScope)->isRequestMethodCall()) {
                    return $this->report($varValue->line);
                }
            }
        }

        return null;
    }

    private function report(int $line): Insight
    {
        return $this->createInsight(
            CWE::CWE_94,
            self::MESSAGE,
            $line,
            Severity::HIGH->value,
        );
    }
}
