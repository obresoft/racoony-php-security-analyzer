<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Laravel;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Resolver\ClassNameResolver;

use function in_array;

final class LaravelDBFacadeAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    public const array DATA_SINK_METHODS = [
        'get',
        'all',
        'first',
        'firstorfail',
        'sole',
        'find',
        'findorfail',
        'pluck',
        'value',
        'paginate',
        'simplepaginate',
        'cursorpaginate',
        'cursor',
        'lazy',
    ];

    private const array DB_FACADE_CLASSES = [
        'Illuminate\Support\Facades\DB',
        'DB',
    ];

    public function __construct(
        private readonly ?ClassNameResolver $classNameResolver,
        protected Scope $scope,
    ) {}

    public function isDBFacade(): bool
    {
        if (!$this->scope->callAnalyzer()->isCallLike()) {
            return false;
        }

        $leftmostReceiverNode = $this->scope->findLeftmostReceiver();

        if ($this->scope->withNode($leftmostReceiverNode)->isVariable()) {
            $receiverVariableName = $this->scope->withNode($leftmostReceiverNode)->getVariableName();
            if (null === $receiverVariableName || '' === $receiverVariableName) {
                return false;
            }

            foreach ($this->scope->withNode($leftmostReceiverNode)->analyzeVariable($receiverVariableName) as $variableFact) {
                $factScope = $variableFact->scope ?? null;
                if (null === $factScope) {
                    continue;
                }

                if (in_array($variableFact->nameOrValue, self::DB_FACADE_CLASSES, true)) {
                    return true;
                }
            }

            return false;
        }

        $receiverClassShortName = $this->scope->withNode($leftmostReceiverNode)->classAsString() ?? '';

        if ('' === $receiverClassShortName) {
            return false;
        }

        $resolvedFullyQualifiedClassName = $this->classNameResolver->resolveClassName($receiverClassShortName);

        if ('' === $resolvedFullyQualifiedClassName) {
            return false;
        }

        return in_array($resolvedFullyQualifiedClassName, self::DB_FACADE_CLASSES, true);
    }

    public function findDataReadScope(): ?Scope
    {
        $selects = [
            'select',
            'addselect',
            'selectraw',
            'value',
            'pluck',
            'count',
            'min',
            'max',
            'avg',
            'sum',
        ];

        foreach ($selects as $select) {
            $scope = $this->scope->callChainAnalyzer()->findLastMethodCallScope($select);
            if (null !== $scope) {
                return $scope;
            }
        }

        return null;
    }

    public function findTableScope(): ?Scope
    {
        return $this->scope->callChainAnalyzer()->findLastMethodCallScope('table');
    }
}
