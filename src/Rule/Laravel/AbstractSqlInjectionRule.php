<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\Laravel\LaravelDBFacadeAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelModelAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRequestCallAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

use function in_array;

abstract class AbstractSqlInjectionRule extends AbstractRule implements Rule
{
    public const array BUILDER_METHODS = [
        'select',
        'addselect',
        'pluck',
        'distinct',
        'orderby',
        'orderbydesc',
        'latest',
        'oldest',
        'groupby',
        'having',
        'wherecolumn',
        'where',
        'orwhere',
        'wherein',
        'wherenotin',
        'wherebetween',
        'whereraw',
        'havingraw',
        'orderbyraw',
        'groupbyraw',
        'selectraw',
        'join',
        'leftjoin',
        'rightjoin',
        'crossjoin',
        'from',
        'fromsub',
        'joinsub',
    ];

    private const string MESSAGE = 'User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).';

    final public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;

        if (!$scope->callAnalyzer()->isCallLike()) {
            return null;
        }

        $methodName = $scope->callAnalyzer()->calleeName() ?? '';

        if (!in_array(strtolower($methodName), $this->methodsToCheck(), true)) {
            return null;
        }

        $modelAnalyzer = $context->analyzerResolver->get(LaravelModelAnalyzer::class);
        $dbFacadeAnalyzer = $context->analyzerResolver->get(LaravelDBFacadeAnalyzer::class);

        if (!$modelAnalyzer->isLaravelModel() && !$dbFacadeAnalyzer->isDBFacade()) {
            return null;
        }

        $collectedInsights = [];
        foreach ($scope->callAnalyzer()->argScopes() as $argumentScope) {
            foreach ($scope->withNode($argumentScope->node())->decomposeArgumentIntoPartScopes() as $partScope) {
                $insight = $this->analyzeScopes($scope, $partScope, $context);
                if (null !== $insight) {
                    $collectedInsights[] = $insight;
                }
            }
        }

        return [] !== $collectedInsights ? $collectedInsights : null;
    }

    abstract protected function methodsToCheck(): array;

    private function analyzeScopes(Scope $scope, Scope $argScope, AnalysisContext $context): ?Insight
    {
        if (!$argScope->isVariable() || $argScope->callAnalyzer()->isCallLike()) {
            return null;
        }

        $requestCallAnalyzer = $context->analyzerResolver->get(LaravelRequestCallAnalyzer::class);
        if ($argScope->isVariable()) {
            $var = $scope->analyzeVariable($argScope->getVariableName());

            foreach ($var as $varValue) {
                $variableScope = $varValue->scope;
                if ($variableScope->callAnalyzer()->isMethodCall()) {
                    if ($requestCallAnalyzer->withScope($variableScope)->isRequestMethodCall()) {
                        return $this->report($scope->getLine());
                    }
                }
            }
        }

        return null;
    }

    private function report(int $line): Insight
    {
        return $this->createInsight(
            CWE::CWE_89,
            self::MESSAGE,
            $line,
            Severity::HIGH->value,
        );
    }
}
