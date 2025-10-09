<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\Laravel\LaravelModelAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRequestCallAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

#[CWE('915', 'Improperly Controlled Modification of Dynamically-Determined Object Attributes', 'https://cwe.mitre.org/data/definitions/915.html')]
final class LaravelMassAssignmentRule extends AbstractRule implements Rule
{
    private const string MESSAGE = 'Potential mass assignment: user-controlled data is passed. Use validated input and explicit attribute mapping (fillable/guarded).';

    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;

        if (!$scope->callAnalyzer()->isCallLike()) {
            return null;
        }

        $laravelModelAnalyzer = $context->analyzerResolver->get(LaravelModelAnalyzer::class);
        $laravelRequestCallAnalyzer = $context->analyzerResolver->get(LaravelRequestCallAnalyzer::class);

        if (!$this->shouldInspectInvocation($scope, $laravelModelAnalyzer)) {
            return null;
        }

        foreach ($this->iterateCandidateArgumentScopes($scope) as ['valueScope' => $valueScope, 'sourceLine' => $sourceLine]) {
            $callAnalyzer = $laravelRequestCallAnalyzer->withScope($valueScope);

            if ($callAnalyzer->isValidatedCall()) {
                continue;
            }

            if ($callAnalyzer->isRequestMethodCall()) {
                return $this->report($sourceLine);
            }
        }

        return null;
    }

    /**
     * @return iterable<array{valueScope: Scope, sourceLine: int}>
     */
    private function iterateCandidateArgumentScopes(Scope $scope): iterable
    {
        foreach ($scope->callAnalyzer()->argScopes() as $argScope) {
            // Case A: array argument like ['name' => $request->get('name')]
            if ($argScope->arrayAnalyzer()->isArray()) {
                $stringKeyToValueScope = $argScope->arrayAnalyzer()->extractArrayStringKeyToValueScopes();
                foreach ($stringKeyToValueScope as $attributeName => $valueScope) {
                    yield ['valueScope' => $valueScope, 'sourceLine' => $valueScope->getLine()];
                }

                continue;
            }

            // Case B: nested function call argument like foo(bar($request->input('x')))
            if ($argScope->callAnalyzer()->isFuncCall()) {
                foreach ($argScope->callAnalyzer()->argScopes() as $nestedArgScope) {
                    yield ['valueScope' => $nestedArgScope, 'sourceLine' => $argScope->getLine()];
                }

                continue;
            }

            yield ['valueScope' => $argScope, 'sourceLine' => $argScope->getLine()];
        }
    }

    private function shouldInspectInvocation(Scope $scope, LaravelModelAnalyzer $laravelModelAnalyzer): bool
    {
        return $scope->callAnalyzer()->hasArgs()
          && $laravelModelAnalyzer->isModelWriteMethodCall()
          && ($scope->callAnalyzer()->isStaticCall() || $scope->callAnalyzer()->isMethodCall());
    }

    private function report(int $line): Insight
    {
        return $this->createInsight(
            CWE::CWE_915,
            self::MESSAGE,
            $line,
            Severity::HIGH->value,
        );
    }
}
