<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\CWE;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\InputAnalyzer;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Recommendation;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

use function sprintf;

/**
 * Scans for function calls such as eval, call_user_func_array, etc.
 *
 * CWE-94: Improper Control of Generation of Code ('Code Injection')
 * @see https://cwe.mitre.org/data/definitions/94.html
 * The product constructs all or part of a code segment using externally-influenced input from an upstream component,
 * but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.
 */
#[CWE('94', "Improper Control of Generation of Code ('Code Injection')", 'https://cwe.mitre.org/data/definitions/94.html')]
final class CodeInjectionRule extends AbstractRule implements Rule
{
    private const string VULNERABILITY_MESSAGE = 'Potential code injection detected: user-controlled input %s is used via the %s. Sanitize input properly before use.';

    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;
        $node = $scope->node();

        if (!($scope->isEval() || $scope->isInclude())) {
            return null;
        }

        $usedFunctionName = $scope->isEval() ? 'eval' : $scope->getIncludeName();
        $codeExpression = $scope->getNodeExpression();
        if (null === $codeExpression) {
            return null;
        }

        $inputAnalyzer = $context->analyzerResolver->get(InputAnalyzer::class);
        $codeExpressionScope = $scope->withNode($codeExpression);

        if ($codeExpressionScope->arrayAnalyzer()->isArrayDimFetch() || $codeExpressionScope->isPropertyFetch()) {
            if ($inputAnalyzer->isUserInputExpr($codeExpressionScope->node())) {
                $rootName = $codeExpressionScope->getRootVariable()->name ?? '';

                return $this->report($node->getLine(), $usedFunctionName, $rootName);
            }
        }

        if ($codeExpressionScope->isVariable()) {
            foreach ($context->scope->analyzeVariable($codeExpressionScope->getVariableName()) as $factData) {
                if ($factData->scope->concatAnalyzer()->isConcat()) {
                    foreach ($factData->meta[0]->meta as $partFact) {
                        if ($inputAnalyzer->isUserInputExpr($partFact->scope->node())) {
                            $rootName = $partFact->scope->getRootVariable()->name ?? '';

                            return $this->report($node->getLine(), $usedFunctionName, $rootName);
                        }
                    }
                }

                if ($inputAnalyzer->isUserInputExpr($factData->scope->node())) {
                    $rootName = $codeExpressionScope->getRootVariable()->name ?? '';

                    return $this->report($node->getLine(), $usedFunctionName, $rootName);
                }
            }
        }

        if ($scope->isEval()) {
            return $this->reportRecommendation($node->getLine(), $usedFunctionName);
        }

        return null;
    }

    private function report(int $lineNumber, string $usedFunctionName, string $userInputVariableName): array|Insight
    {
        return $this->createInsight(
            CWE::CWE_94,
            sprintf(self::VULNERABILITY_MESSAGE, $userInputVariableName, $usedFunctionName),
            $lineNumber,
            Severity::HIGH->value,
        );
    }

    private function reportRecommendation(int $lineNumber, string $usedFunctionName): array|Insight
    {
        return $this->createInsight(
            CWE::CWE_94,
            sprintf(
                'Potential code injection detected: user-controlled via the %s. Sanitize input properly before use.',
                $usedFunctionName,
            ),
            $lineNumber,
            insight: Recommendation::class,
        );
    }
}
