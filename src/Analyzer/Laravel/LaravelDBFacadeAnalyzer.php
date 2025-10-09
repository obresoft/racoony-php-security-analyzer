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
    private const array DB_FACADE_CLASSES = ['Illuminate\Support\Facades\DB'];

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
}
