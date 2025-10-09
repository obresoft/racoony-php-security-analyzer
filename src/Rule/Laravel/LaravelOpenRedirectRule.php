<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\InputAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRedirectAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRequestCallAnalyzer;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

/**
 * CWE-601: URL Redirection to Untrusted Site ('Open Redirect').
 * @see https://cwe.mitre.org/data/definitions/601.html
 * The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.
 */
#[CWE('601', "URL Redirection to Untrusted Site ('Open Redirect')", 'https://cwe.mitre.org/data/definitions/601.html')]
final class LaravelOpenRedirectRule extends AbstractRule implements Rule
{
    private const string MSG = 'Potential open redirect vulnerability detected. Validate and whitelist redirect URLs.';

    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;
        $redirectAnalyzer = $context->analyzerResolver->get(LaravelRedirectAnalyzer::class);
        $inputDetector = $context->analyzerResolver->get(InputAnalyzer::class);
        $requestAnalyzer = $context->analyzerResolver->get(LaravelRequestCallAnalyzer::class);

        if (!$scope->callAnalyzer()->isCallLike()) {
            return null;
        }

        if ($scope->callAnalyzer()->isCallLike() && !$redirectAnalyzer->isDangerousMethodCall()) {
            return null;
        }

        if ($scope->callAnalyzer()->hasArgs() && $requestAnalyzer->anyArgResolvesToRequest()) {
            return $this->report($scope->getLine());
        }

        if ($inputDetector->anyArgIsUserInput()) {
            return $this->report($scope->getLine());
        }

        foreach ($scope->callAnalyzer()->argScopes() as $argScope) {
            $laravelRequestCallAnalyzer = new LaravelRequestCallAnalyzer($argScope, $this->nameResolver);
            if ($laravelRequestCallAnalyzer->isRequestMethodCall()) {
                return $this->report($scope->getLine());
            }
        }

        return null;
    }

    private function report(int $line): Insight
    {
        return $this->createInsight(
            CWE::CWE_601,
            self::MSG,
            $line,
            Severity::HIGH->value,
        );
    }
}
