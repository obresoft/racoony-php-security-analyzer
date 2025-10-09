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

/**
 * Base rule for "required middleware must appear in the 'web' group".
 * Subclasses define the target middleware, CWE, and message.
 */
abstract class AbstractLaravelRequiredWebMiddlewareRule extends AbstractRule implements Rule
{
    final public function check(AnalysisContext $context): null|array|Insight
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

    /**
     * @return array<int, ClassConstFetch|string>
     */
    protected function extractValuesRecursively(mixed $value): array
    {
        $out = [];

        $add = static function (ClassConstFetch $c) use (&$out): void {
            $ref = (string)$c->class;
            if (!in_array($ref, $out, true)) {
                $out[] = $ref;
            }
        };

        $visit = static function (mixed $v) use (&$visit, $add): void {
            if ($v instanceof ClassConstFetch) {
                $add($v);

                return;
            }

            if (!is_array($v)) {
                return;
            }

            if (isset($v['type'], $v['value'])) {
                if ('complex_expression' === $v['type'] && ($v['node'] ?? null) instanceof ClassConstFetch) {
                    $add($v['node']);

                    return;
                }
                if ('array' === $v['type']) {
                    foreach ($v['value'] as $item) {
                        $visit($item);
                    }

                    return;
                }

                return;
            }

            foreach ($v as $nested) {
                $visit($nested);
            }
        };

        $visit($value);

        return $out;
    }

    private function checkLaravelLessThan11(AnalysisContext $context): null|array|Insight
    {
        /** @var Class_ $node */
        $node = $context->scope->node();
        $classAnalyzer = new ClassAnalyzer();
        $classData = $classAnalyzer->analyzeClass($node);
        $classNameResolver = new ClassNameResolver($context->scope->getNodes());

        if ('Illuminate\Foundation\Http\Kernel' !== $classNameResolver->resolveClassName($classData['extends'])) {
            return null;
        }

        foreach ($classAnalyzer->analyzeProperties($node) as $property) {
            if ('middlewareGroups' !== $property['name']) {
                continue;
            }

            $values = $this->extractValuesRecursively($property['value']);

            $found = false;
            foreach ($values as $value) {
                $resolvedClass = $classNameResolver->resolveClassName($value);
                $classData = $context->projectDataFlowIndex->getClassData($resolvedClass);

                if ($classData?->parentClass === $this->requiredMiddleware()) {
                    $found = true;

                    break;
                }

                if ($this->requiredMiddleware() === $resolvedClass) {
                    $found = true;

                    break;
                }
            }

            return $found ? null : $this->reportMissing($property['line']);
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
