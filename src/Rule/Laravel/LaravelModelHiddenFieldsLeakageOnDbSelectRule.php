<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\Laravel\LaravelDBFacadeAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Attribute\SensitiveFieldsAttribute;
use Obresoft\Racoony\DataFlow\ClassDataDto;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Resolver\SqlTableNameAndAliasResolver;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;
use Obresoft\Racoony\Support\Selector;

use function in_array;
use function is_string;
use function sprintf;

#[CWE('201', 'Insertion of Sensitive Information Into Sent Data', 'https://cwe.mitre.org/data/definitions/201.html')]
final class LaravelModelHiddenFieldsLeakageOnDbSelectRule extends AbstractRule implements Rule
{
    public function check(AnalysisContext $context): ?Insight
    {
        $dbFacadeAnalyzer = $context->analyzerResolver->get(LaravelDBFacadeAnalyzer::class);

        if (!$dbFacadeAnalyzer->isDBFacade()) {
            return null;
        }

        $scope = $context->scope;

        $methodName = $scope->nameAsString();
        if (null === $methodName) {
            return null;
        }

        $methodName = strtolower($methodName);

        if (!in_array($methodName, LaravelDBFacadeAnalyzer::DATA_SINK_METHODS, true)) {
            return null;
        }

        $findTableScope = $dbFacadeAnalyzer->findTableScope();
        if (null === $findTableScope) {
            return null;
        }

        $tableArgumentScope = $findTableScope->callAnalyzer()->firstArgScope();
        $tableArgumentStringValue = $tableArgumentScope?->stringValue();

        if (!is_string($tableArgumentStringValue) || '' === $tableArgumentStringValue) {
            return null;
        }

        $resolvedTable = (new SqlTableNameAndAliasResolver())->resolveFromString($tableArgumentStringValue);

        $projectDataFlowIndex = $context->projectDataFlowIndex;

        /** @var ClassDataDto|null $classData */
        $classData = $projectDataFlowIndex->getClassByTable($resolvedTable->tableName);

        /** @var list<string> $hiddenAttributeNames */
        $hiddenAttributeNames = $this->resolveHiddenFields($classData);

        if ([] === $hiddenAttributeNames) {
            return null;
        }

        $selectScope = $dbFacadeAnalyzer->findDataReadScope();

        if (null === $selectScope) {
            return $this->report($scope->getLine(), $hiddenAttributeNames, $resolvedTable->tableName);
        }

        $selectedColumnNames = $this->extractSelectedColumnNames($selectScope);

        if ([] === $selectedColumnNames) {
            return null;
        }

        // If select contains '*' or 'alias.*' we must assume hidden fields are included.
        if (Selector::containsWildcardSelection($selectedColumnNames)) {
            return $this->report($selectScope->getLine(), $hiddenAttributeNames, $resolvedTable->tableName);
        }

        $leakedHiddenFieldNames = [];
        foreach ($selectedColumnNames as $selectedColumnName) {
            $normalizedColumnName = $this->normalizeSelectedColumnName($selectedColumnName);

            if (null === $normalizedColumnName) {
                continue;
            }

            if (in_array($normalizedColumnName, $hiddenAttributeNames, true)) {
                $leakedHiddenFieldNames[$normalizedColumnName] = true;
            }
        }

        if ([] === $leakedHiddenFieldNames) {
            return null;
        }

        $leakedHiddenFieldNameList = array_keys($leakedHiddenFieldNames);

        return $this->report($selectScope->getLine(), $leakedHiddenFieldNameList, $resolvedTable->tableName);
    }

    /**
     * @return list<string>
     */
    private function extractSelectedColumnNames(Scope $selectScope): array
    {
        $selectedColumnNames = [];

        foreach ($selectScope->callAnalyzer()->argScopes() as $argumentScope) {
            foreach ($argumentScope->decomposeArgumentIntoPartScopes() as $partScope) {
                foreach ($this->extractColumnNamesFromPartScope($partScope) as $columnName) {
                    $selectedColumnNames[] = $columnName;
                }
            }
        }

        return $selectedColumnNames;
    }

    /**
     * @return list<string>
     */
    private function extractColumnNamesFromPartScope(Scope $partScope): array
    {
        if ($partScope->isVariable()) {
            $resolvedColumnNames = [];

            $variableName = $partScope->getVariableName();
            $variableAnalyzer = $partScope->getAnalyzeVariable();

            foreach ($variableAnalyzer->analyzeVariable($variableName, $partScope) as $resolvedScope) {
                foreach ($this->extractColumnNamesFromPartScope($resolvedScope->scope) as $columnName) {
                    $resolvedColumnNames[] = $columnName;
                }
            }

            return $resolvedColumnNames;
        }

        if ($partScope->arrayAnalyzer()->isArray()) {
            return $this->extractStringItemsFromArrayScope($partScope);
        }

        $stringLiteralValue = $partScope->stringValue();
        if (is_string($stringLiteralValue) && '' !== $stringLiteralValue) {
            return [$stringLiteralValue];
        }

        return [];
    }

    /**
     * @return list<string>
     */
    private function extractStringItemsFromArrayScope(Scope $arrayScope): array
    {
        $columnNames = [];

        foreach ($arrayScope->decomposeArgumentIntoPartScopes() as $arrayItemScope) {
            if ($arrayItemScope->arrayAnalyzer()->isArray()) {
                foreach ($this->extractStringItemsFromArrayScope($arrayItemScope) as $nestedColumnName) {
                    $columnNames[] = $nestedColumnName;
                }

                continue;
            }

            $arrayItemStringValue = $arrayItemScope->stringValue();
            if (is_string($arrayItemStringValue) && '' !== $arrayItemStringValue) {
                $columnNames[] = $arrayItemStringValue;
            }
        }

        return $columnNames;
    }

    /**
     * @return non-empty-string|null
     */
    private function normalizeSelectedColumnName(string $selectedColumnName): ?string
    {
        $value = trim($selectedColumnName);

        if ('' === $value) {
            return null;
        }

        $value = preg_split('/\s+as\s+/i', $value, 2)[0] ?? $value;

        $value = str_replace('`', '', $value);

        $dotPosition = strrpos($value, '.');
        if (false !== $dotPosition) {
            $value = substr($value, $dotPosition + 1);
        }

        $value = trim($value);

        return '' !== $value ? $value : null;
    }

    /**
     * @return list<string>
     */
    private function resolveHiddenFields(?ClassDataDto $classData): array
    {
        if (null === $classData) {
            return [];
        }

        $fromAttribute = array_values($classData->classAttributes[SensitiveFieldsAttribute::class][0] ?? []);
        if ([] !== $fromAttribute) {
            return $fromAttribute;
        }

        return array_values(array_filter(
            $classData->properties['hidden'] ?? [],
            static fn ($value): bool => is_string($value) && '' !== $value,
        ));
    }

    private function report(int $line, array $leakedHiddenFieldNames, string $tableName): Insight
    {
        $message = sprintf(
            'Hidden fields leakage detected: selecting hidden attribute(s) [%s] from table "%s".',
            implode(', ', $leakedHiddenFieldNames),
            $tableName,
        );

        return $this->createInsight(
            CWE::CWE_201,
            $message,
            $line,
            Severity::MEDIUM->value,
        );
    }
}
