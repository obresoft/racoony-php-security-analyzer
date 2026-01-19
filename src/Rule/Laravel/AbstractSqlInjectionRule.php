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
use function sprintf;
use function strtolower;

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

    private const string MESSAGE =
        'User input from %s flows into %s as SQL identifier%s. Parameter binding does not sanitize identifiers. Potential SQL Injection (CWE-89).';

    final public function check(AnalysisContext $context): ?array
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

        if (!$modelAnalyzer->isLaravelModelFromClassNode() && !$dbFacadeAnalyzer->isDBFacade()) {
            return null;
        }

        $collectedInsights = [];

        foreach ($scope->callAnalyzer()->argScopes() as $argumentScope) {
            foreach ($scope->withNode($argumentScope->node())->decomposeArgumentIntoPartScopes() as $partScope) {
                $insight = $this->analyzeScopes($scope, $partScope, $context, $methodName);
                if ($insight instanceof Insight) {
                    $collectedInsights[] = $insight;
                }
            }
        }

        return [] !== $collectedInsights ? $collectedInsights : null;
    }

    abstract protected function methodsToCheck(): array;

    private function analyzeScopes(
        Scope $scope,
        Scope $argScope,
        AnalysisContext $context,
        string $sinkMethod,
    ): ?Insight {
        $requestCallAnalyzer = $context->analyzerResolver->get(LaravelRequestCallAnalyzer::class);

        if ($argScope->callAnalyzer()->isCallLike()
            && $requestCallAnalyzer->withScope($argScope)->isRequestMethodCall()
        ) {
            $source = 'Request::' . ($argScope->callAnalyzer()->calleeName() ?? 'unknown') . '()';

            return $this->report(
                $scope->getLine(),
                $sinkMethod,
                $source,
                null,
            );
        }

        if ($argScope->isVariable()) {
            $variableName = $argScope->getVariableName();
            $variable = $scope->analyzeVariable($variableName);

            foreach ($variable as $varValue) {
                $variableScope = $varValue->scope;

                if ($variableScope->callAnalyzer()->isMethodCall()
                    && $requestCallAnalyzer->withScope($variableScope)->isRequestMethodCall()
                ) {
                    $source = 'Request::' . ($variableScope->callAnalyzer()->calleeName() ?? 'unknown') . '()';

                    return $this->report(
                        $scope->getLine(),
                        $sinkMethod,
                        $source,
                        '$' . $variableName,
                    );
                }
            }
        }

        return null;
    }

    private function report(
        int $line,
        string $sinkMethod,
        string $source,
        ?string $variable,
    ): Insight {
        return $this->createInsight(
            CWE::CWE_89,
            sprintf(
                self::MESSAGE,
                $source,
                $sinkMethod . '()',
                null !== $variable ? ' (variable: ' . $variable . ')' : ' (direct argument)',
            ),
            $line,
            Severity::HIGH->value,
        );
    }
}
