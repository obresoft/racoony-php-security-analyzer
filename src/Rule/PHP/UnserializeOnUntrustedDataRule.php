<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\PHP;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\InputAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRequestCallAnalyzer;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

#[CWE('502', 'Deserialization of Untrusted Data', 'https://cwe.mitre.org/data/definitions/502.html')]
final class UnserializeOnUntrustedDataRule extends AbstractRule implements Rule
{
    private const string UNSERIALIZE_METHOD = 'unserialize';

    private const string MESSAGE = 'Do not call unserialize() on user-controlled data. This can lead to PHP Object Injection and potentially code execution depending on available gadget chains. Use JSON or a safe serialization format instead.';

    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;

        if (!$scope->callAnalyzer()->isFunctionNamed(self::UNSERIALIZE_METHOD)) {
            return null;
        }

        $inputAnalyzer = $context->analyzerResolver->get(InputAnalyzer::class);
        $requestAnalyzer = $context->analyzerResolver->get(LaravelRequestCallAnalyzer::class);
        $methodArgument = $scope->callAnalyzer()->firstArgScope();

        if ($methodArgument->isVariable()) {
            $variableFacts = $scope->analyzeVariable($methodArgument->getVariableName());

            foreach ($variableFacts as $variableFact) {
                $variableScope = $variableFact->scope;
                if ($inputAnalyzer->withScope($variableScope)->isUserControlledInput()
                    || $requestAnalyzer->withScope(
                        $variableScope,
                    )->isRequestMethodCall()) {
                    return $this->report($scope->getLine());
                }
            }
        }

        if ($inputAnalyzer->withScope($methodArgument)->isUserControlledInput()
            || $requestAnalyzer->withScope(
                $methodArgument,
            )->isRequestMethodCall()) {
            return $this->report($scope->getLine());
        }

        return [];
    }

    private function report(int $line): Insight
    {
        return $this->createInsight(
            CWE::CWE_502,
            self::MESSAGE,
            $line,
            Severity::HIGH->value,
        );
    }
}
