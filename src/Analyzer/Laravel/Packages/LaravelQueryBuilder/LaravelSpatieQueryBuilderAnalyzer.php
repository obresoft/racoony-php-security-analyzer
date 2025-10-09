<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Laravel\Packages\LaravelQueryBuilder;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;

use function is_string;

final class LaravelSpatieQueryBuilderAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    private const BUILDER_CLASS_NAME = 'Spatie\QueryBuilder\QueryBuilder';

    private const string ALLOWED_SORT_CLASS_NAME = 'Spatie\QueryBuilder\AllowedSort';

    private const string ALLOWED_FILTER_CALL = 'Spatie\QueryBuilder\AllowedFilter';

    public function __construct(
        protected Scope $scope,
        private readonly ?ClassNameResolver $resolver = null,
    ) {}

    /**
     * Checks if the current node is a call on Spatie\QueryBuilder\QueryBuilder.
     */
    public function isSpatieQueryBuilderCall(): bool
    {
        if (!$this->scope->callAnalyzer()->isMethodCall()) {
            return false;
        }

        $call = $this->scope->matchMethodCall();
        $leftmostReceiver = $this->scope->withNode($call->var)->findLeftmostReceiver();

        if ($leftmostReceiver instanceof Expr\StaticCall && $leftmostReceiver->class instanceof Name) {
            $resolvedType = $this->resolver?->resolveClassName($leftmostReceiver->class->name);

            return self::BUILDER_CLASS_NAME === $resolvedType;
        }

        if ($leftmostReceiver instanceof Variable && is_string($leftmostReceiver->name)) {
            $resolvedType = $this->resolver?->resolveVariableType($leftmostReceiver->name);

            return self::BUILDER_CLASS_NAME === $resolvedType;
        }

        return false;
    }

    public function isAllowedSortCall(): bool
    {
        return $this->isClassCall(self::ALLOWED_SORT_CLASS_NAME);
    }

    public function isAllowedFilterCall(): bool
    {
        return $this->isClassCall(self::ALLOWED_FILTER_CALL);
    }

    private function isClassCall(string $classCall): bool
    {
        $className = $this->resolver?->resolveClassName($this->scope->callAnalyzer()->getCalledMethodClassName());

        return $classCall === $className;
    }
}
