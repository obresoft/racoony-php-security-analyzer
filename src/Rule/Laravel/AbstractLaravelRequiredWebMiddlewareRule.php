<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\Node\ClassAnalyzer;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Stmt\Class_;

use function in_array;
use function is_array;

abstract class AbstractLaravelRequiredWebMiddlewareRule extends AbstractRule implements Rule
{
    final public function check(AnalysisContext $context): ?Insight
    {
        $scope = $context->scope;

        if ($context->applicationData->frameworkVersion < '11' && $scope->isClassLikeCall('App\Http\Kernel')) {
            return $this->checkLaravelLessThan11($context);
        }

        return null;
    }

    /**
     * Subclasses must return the fully-qualified middleware class name
     * e.g. 'Illuminate\Cookie\Middleware\EncryptCookies'.
     */
    abstract protected function requiredMiddleware(): string;

    abstract protected function cwe(): string;

    abstract protected function message(): string;

    protected function extractValuesRecursively(mixed $value): array
    {
        $out = [];

        array_walk_recursive($value, static function ($item) use (&$out): void {
            $node = null;

            if ($item instanceof ClassConstFetch) {
                $node = $item;
            } elseif (is_array($item) && ($item['node'] ?? null) instanceof ClassConstFetch) {
                $node = $item['node'];
            }

            if ($node) {
                $ref = (string)$node->class;
                if (!in_array($ref, $out, true)) {
                    $out[] = $ref;
                }
            }
        });

        return $out;
    }

    private function checkLaravelLessThan11(AnalysisContext $context): ?Insight
    {
        /** @var Class_ $node */
        $node = $context->scope->node();
        $classAnalyzer = new ClassAnalyzer();
        $classNameResolver = new ClassNameResolver($context->scope->getNodes());

        $classData = $classAnalyzer->analyzeClass($node);
        if ('Illuminate\Foundation\Http\Kernel' !== $classNameResolver->resolveClassName($classData['extends'])) {
            return null;
        }

        foreach ($classAnalyzer->analyzeProperties($node) as $property) {
            if ('middlewareGroups' !== $property['name']) {
                continue;
            }

            $values = $this->extractValuesRecursively($property['value']);
            $required = $this->requiredMiddleware();

            foreach ($values as $value) {
                $resolved = $classNameResolver->resolveClassName($value);
                $targetData = $context->projectDataFlowIndex->getClassData($resolved);

                if ($resolved === $required || ($targetData?->parentClass === $required)) {
                    return null;
                }
            }

            return $this->reportMissing($property['line']);
        }

        return null;
    }

    private function reportMissing(int $line): Insight
    {
        return $this->createInsight(
            $this->cwe(),
            $this->message(),
            $line,
            Severity::HIGH->value,
        );
    }
}
