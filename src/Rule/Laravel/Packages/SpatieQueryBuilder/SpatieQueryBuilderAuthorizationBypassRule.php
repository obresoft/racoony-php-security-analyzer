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
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

use function in_array;

/**
 * Detects authorization bypass risks when user-controlled input is used to build
 * includes or sparse fieldsets in spatie/laravel-query-builder.
 *
 * Triggers on:
 *  - ->allowedIncludes(<user input>)
 *  - ->allowedFields(<user input>)
 *
 * Rationale: letting a user pick relations or fields can reveal unauthorized data (IDOR-like).
 */
#[CWE('639', 'Authorization Bypass Through User-Controlled Key', 'https://cwe.mitre.org/data/definitions/639.html')]
final class SpatieQueryBuilderAuthorizationBypassRule extends AbstractRule implements Rule
{
    /** @var array<string> */
    private const array TARGET_METHODS = [
        'allowedIncludes',
        'allowedFields',
    ];

    private const string MESSAGE = 'User-controlled include/fieldset may bypass authorization. An attacker can request unauthorized relations or fields.';

    public function check(AnalysisContext $context): null|array|Insight
    {
        $currentScope = $context->scope;
        $callAnalyzer = $currentScope->callAnalyzer();

        if (!$callAnalyzer->isCallLike()) {
            return null;
        }

        $calleeName = $callAnalyzer->calleeName();

        if (!in_array($calleeName, self::TARGET_METHODS, true)) {
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
            $normalizedArgumentScope = $this->normalizeToRootVariableIfPossible($argumentScope);

            // Safe case: explicit literal allow-list like ['author', 'comments', etc...] should not be reported.
            if ($normalizedArgumentScope->arrayAnalyzer()->isArray()) {
                continue;
            }

            if ($inputAnalyzer->withScope($normalizedArgumentScope)->isUserInputExpr()) {
                $vulnerabilities[] = $this->report($normalizedArgumentScope->getLine());

                continue;
            }

            if ($laravelRequestAnalyzer->withScope($normalizedArgumentScope)->isRequestMethodCall()) {
                $vulnerabilities[] = $this->report($normalizedArgumentScope->getLine());
            }
        }

        return empty($vulnerabilities) ? null : $vulnerabilities;
    }

    private function normalizeToRootVariableIfPossible(Scope $argumentScope): Scope
    {
        if (($argumentScope->arrayAnalyzer()->isArrayDimFetch() || $argumentScope->isPropertyFetch()) && isset($argumentScope->node()->var)) {
            $rootVariable = $argumentScope->getRootVariable();
            if (null !== $rootVariable) {
                return $argumentScope->withNode($rootVariable);
            }
        }

        return $argumentScope;
    }

    private function report(int $line): Insight
    {
        return $this->createInsight(
            CWE::CWE_639,
            self::MESSAGE,
            $line,
            Severity::HIGH->value,
        );
    }
}
