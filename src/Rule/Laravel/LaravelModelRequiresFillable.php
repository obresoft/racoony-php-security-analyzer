<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\Laravel\LaravelModelAnalyzer;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;

/**
 * CWE-915:Improperly Controlled Modification of Dynamically-Determined Object Attributes
 * The product receives input from an upstream component that specifies multiple attributes, properties,
 * or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified.
 * @see https://cwe.mitre.org/data/definitions/915.html
 * Also @see https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html#mass-assignment
 */
#[CWE('915', 'Improperly Controlled Modification of Dynamically-Determined Object Attributes', 'https://cwe.mitre.org/data/definitions/915.html')]
final class LaravelModelRequiresFillable extends AbstractRule implements Rule
{
    public function check(AnalysisContext $context): null|array|Insight
    {
        if (!$context->scope->isClassCall()) {
            return null;
        }

        $laravelModelAnalyzer = $context->analyzerResolver->get(LaravelModelAnalyzer::class);

        if (!$laravelModelAnalyzer->isLaravelModel()) {
            return null;
        }

        if (!$laravelModelAnalyzer->hasFillableOrGuarded()) {
            return $this->createInsight(
                CWE::CWE_915,
                'Missing `$fillable` property in model, which may lead to mass assignment vulnerabilities.',
                0,
                Severity::HIGH->value,
            );
        }

        return null;
    }
}
