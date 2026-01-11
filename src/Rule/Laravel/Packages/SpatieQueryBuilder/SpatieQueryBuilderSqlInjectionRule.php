<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel\Packages\SpatieQueryBuilder;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\InputAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRequestCallAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\Packages\LaravelQueryBuilder\LaravelSpatieQueryBuilderAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Laravel\AbstractSqlInjectionRule;
use Obresoft\Racoony\Rule\Rule;

use function in_array;

/**
 * Detects potential SQL Injection by allowing user-controlled identifiers to flow into sorting APIs
 * of spatie/laravel-query-builder.
 *
 * Triggers on:
 *  - ->allowedSorts(<user input>)
 *  - ->defaultSort(<user input>)
 *  - ->allowedSorts([AllowedSort::custom(<user input>, ...)])
 *
 * We focus on identifier-driven SQLi risk (column/table/order) rather than value placeholders.
 */
#[CWE('89', "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", 'https://cwe.mitre.org/data/definitions/89.html')]
final class SpatieQueryBuilderSqlInjectionRule extends AbstractRule implements Rule
{
    /** @var array<string> */
    private const array QUERY_BUILDER_METHODS = [
        'allowedSorts',
        'defaultSort',
        'allowedFilters',
    ];

    /** @var string[] */
    private const SUSPICIOUS_RAW_METHODS = [
        'selectraw', 'addselectraw',
        'whereraw', 'orwhereraw',
        'havingraw', 'orhavingraw',
        'orderbyraw', 'groupbyraw',
        'joinraw', 'leftjoinraw', 'rightjoinraw', 'crossjoinraw',
        'fromraw', 'unionraw',
    ];

    /** @var string[] */
    private const ALLOWED_FILTER_CALLBACK_METHODS = ['callback', 'scope'];

    private const string MESSAGE = 'User-controlled identifier (column/table/order) used in SQL context. Potential SQL Injection (CWE-89).';

    public function check(AnalysisContext $context): null|array|Insight
    {
        $currentScope = $context->scope;
        $callAnalyzer = $currentScope->callAnalyzer();

        if (!$callAnalyzer->isCallLike()) {
            return null;
        }

        $calleeName = $callAnalyzer->calleeName();
        if (!in_array($calleeName, self::QUERY_BUILDER_METHODS, true)) {
            return null;
        }

        $spatieQueryBuilderAnalyzer = $context->analyzerResolver->get(LaravelSpatieQueryBuilderAnalyzer::class);

        if (!$spatieQueryBuilderAnalyzer->isSpatieQueryBuilderCall()) {
            return null;
        }

        $inputAnalyzer = $context->analyzerResolver->get(InputAnalyzer::class);
        $laravelRequestAnalyzer = $context->analyzerResolver->get(LaravelRequestCallAnalyzer::class);

        $vulnerabilities = [];

        foreach ($callAnalyzer->argScopes() as $argumentScope) {
            if ($argumentScope->arrayAnalyzer()->isArray()) {
                $vulnerabilities = array_merge(
                    $vulnerabilities,
                    $this->scanArrayForAllowedSortCustomWithUserInput(
                        $argumentScope,
                        $currentScope,
                        $inputAnalyzer,
                        $laravelRequestAnalyzer,
                    ),
                );

                if ('allowedFilters' === $calleeName) {
                    $vulnerabilities = array_merge(
                        $vulnerabilities,
                        $this->scanAllowedFiltersCallbacksUserInput(
                            $argumentScope,
                            $context,
                        ),
                    );
                }

                continue;
            }

            if ($inputAnalyzer->withScope($argumentScope)->isUserInputExpr()) {
                $vulnerabilities[] = $this->report($argumentScope->getLine());

                continue;
            }

            if ($laravelRequestAnalyzer->withScope($argumentScope)->isRequestMethodCall()) {
                $vulnerabilities[] = $this->report($argumentScope->getLine());
            }
        }

        return empty($vulnerabilities) ? null : $vulnerabilities;
    }

    private function normalizeToRootVariableIfPossible(Scope $argumentScope): Scope
    {
        return $argumentScope;
    }

    /**
     * @return array<int, Insight>
     */
    private function scanArrayForAllowedSortCustomWithUserInput(
        Scope $arrayScope,
        Scope $currentScope,
        InputAnalyzer $inputAnalyzer,
        LaravelRequestCallAnalyzer $laravelRequestAnalyzer,
    ): array {
        $foundInsights = [];
        /** @var Scope $scope */
        foreach ($arrayScope->arrayAnalyzer()->getArrayValueScopesRecursively() as $scope) {
            // AllowedSort::custom(...)
            if (!$scope->callAnalyzer()->isStaticCall()) {
                return $foundInsights;
            }

            $laravelSpatieQueryBuilderAnalyzer = new LaravelSpatieQueryBuilderAnalyzer($scope, new ClassNameResolver($currentScope->getNodes()));
            $laravelSpatieQueryBuilderAnalyzer->isAllowedSortCall();
            $isAllowedSortCustom = $laravelSpatieQueryBuilderAnalyzer->isAllowedSortCall() && 'custom' === $scope->callAnalyzer()->calleeName();

            if (!$isAllowedSortCustom) {
                continue;
            }

            $firstArgScope = $scope->callAnalyzer()->firstArgScope();
            if (null === $firstArgScope) {
                continue;
            }

            $firstArgScope = $this->normalizeToRootVariableIfPossible($firstArgScope);

            if ($inputAnalyzer->withScope($firstArgScope)->isUserInputExpr()
                || $laravelRequestAnalyzer->withScope($firstArgScope)->isRequestMethodCall()
            ) {
                $foundInsights[] = $this->report($firstArgScope->getLine());
            }
        }

        return $foundInsights;
    }

    private function scanAllowedFiltersCallbacksUserInput(
        ?Scope $argumentScope,
        AnalysisContext $context,
    ): array {
        $foundInsights = [];

        if (null === $argumentScope) {
            return $foundInsights;
        }

        foreach ($argumentScope->arrayAnalyzer()->getArrayValueScopesRecursively() as $arrayScope) {
            if (!$arrayScope->callAnalyzer()->isStaticCall()) {
                return $foundInsights;
            }

            $laravelSpatieQueryBuilderAnalyzer = new LaravelSpatieQueryBuilderAnalyzer($arrayScope, new ClassNameResolver($arrayScope->getNodes()));
            $laravelSpatieQueryBuilderAnalyzer->isAllowedFilterCall();
            $isAllowedSortCustom = $laravelSpatieQueryBuilderAnalyzer->isAllowedFilterCall() && in_array($arrayScope->callAnalyzer()->calleeName(), self::ALLOWED_FILTER_CALLBACK_METHODS, true);

            if (!$isAllowedSortCustom) {
                continue;
            }

            $argumentScope = $arrayScope->callAnalyzer()->getSecondArgumentAsScope();

            if (null === $argumentScope) {
                continue;
            }

            foreach ($argumentScope->closureAnalyzer()->closureInvocationScopes() as $innerArgScope) {
                $methodName = $innerArgScope->callAnalyzer()->calleeName() ?? '';

                if (!in_array(strtolower($methodName), AbstractSqlInjectionRule::BUILDER_METHODS, true)) {
                    continue;
                }

                foreach ($innerArgScope->callAnalyzer()->argScopes() as $decomposedScope) {
                    if ($decomposedScope->isInterpolatedString()) {
                        foreach ($decomposedScope->interpolatedPartScopes() as $interpolatedPartScope) {
                            if ($interpolatedPartScope->isVariable() && in_array(strtolower($methodName), self::SUSPICIOUS_RAW_METHODS, true)) {
                                $foundInsights[] = $this->report($interpolatedPartScope->getLine());
                            }
                        }

                        continue;
                    }

                    $insight = $this->analyzeScopes($innerArgScope, $decomposedScope, $context);
                    if (null !== $insight) {
                        $foundInsights[] = $insight;
                    }
                }
            }
        }

        return $foundInsights;
    }

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
                if ($requestCallAnalyzer->withScope($variableScope)->isRequestMethodCall()) {
                    return $this->report($scope->getLine());
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
