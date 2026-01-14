<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\PHP;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

use function in_array;
use function sprintf;

#[CWE('532', 'Insertion of Sensitive Information into Log File.', 'https://cwe.mitre.org/data/definitions/532.html')]
final class MissingSensitiveParameterAttributeRule extends AbstractRule implements Rule
{
    private const string MESSAGE = 'Parameter %s may hold sensitive data but is missing #[\SensitiveParameter] attribute. Consider adding it.';

    /** @var array<string> */
    private const array SENSITIVE_NAMES = [
        'password',
        'pass',
        'pwd',
        'secret',
        'token',
        'apikey',
        'api_key',
        'auth',
        'credential',
        'creditcard',
        'ssn',
        'apitoken',
    ];

    public function check(AnalysisContext $context): ?Insight
    {
        $scope = $context->scope;
        $paramAnalyzer = $scope->paramAnalyzer();

        if (!$paramAnalyzer->isParameter()) {
            return null;
        }

        $parameterName = $paramAnalyzer->getParameterName();

        if ('' === $parameterName) {
            return null;
        }

        foreach ($paramAnalyzer->getAttributesAsScope() as $attributeScope) {
            $attributeAnalyzer = $scope->attributeAnalyzer()->withScope($attributeScope);
            if ($attributeAnalyzer->matchesName('SensitiveParameter')) {
                return null;
            }
        }

        // heuristic
        $lower = strtolower($parameterName);

        if (in_array($lower, self::SENSITIVE_NAMES, true)) {
            return $this->report($scope->getLine(), '$' . $parameterName);
        }

        return null;
    }

    private function report(int $line, $parameterName): Insight
    {
        return $this->createInsight(
            CWE::CWE_532,
            sprintf(self::MESSAGE, $parameterName),
            $line,
            Severity::LOW->value,
        );
    }
}
