<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Laravel;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\DataFlow\ClassDataDto;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use Obresoft\Racoony\Support\Selector;
use PhpParser\Node\Stmt\Class_;
use RuntimeException;

use function array_key_exists;
use function in_array;
use function is_array;

final class LaravelModelAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    private const array LARAVEL_MODEL_CLASS = [
        'Illuminate\Database\Eloquent\Model',
        'Illuminate\Foundation\Auth\User',
    ];

    /** @var list<string> */
    private const array STATIC_SINK_METHODS = [
        'create',
        'forcecreate',
        'update',
        'insert',
        'updateorcreate',
        'firstorcreate',
        'update',
        'upsert',
        'fill',
        'forcefill',
    ];

    public function __construct(
        private readonly ?ClassNameResolver $resolver,
        protected Scope $scope,
        public ?ProjectDataFlowIndex $projectDataFlowIndex = null,
    ) {}

    public function isLaravelModelFromClassNode(): bool
    {
        $scope = $this->scope;
        $node = $scope->node();
        if ($scope->callAnalyzer()->isCallLike()) {
            $leftmostReceiverNode = $this->scope->findLeftmostReceiver();
            $receiverScope = $scope->withNode($leftmostReceiverNode);
            $className = $receiverScope->classAsString() ?? '';
            $resolvedClassName = $this->resolver->resolveClassName($className);
            $classData = $this->projectDataFlowIndex->getClassData($resolvedClassName);

            return in_array($classData->parentClass ?? '', self::LARAVEL_MODEL_CLASS, true);
        }

        if (!$node instanceof Class_ || !$node->extends) {
            return false;
        }

        if (!$this->resolver instanceof ClassNameResolver) {
            throw new RuntimeException('ClassNameResolver is not set. Cannot resolve parent class name.');
        }

        $resolvedParent = $this->resolver->resolveClassName($node->extends);

        return in_array($resolvedParent, self::LARAVEL_MODEL_CLASS, true);
    }

    public function hasProperty(string $propertyName): bool
    {
        return null !== $this->getPropertyValue($propertyName);
    }

    public function getPropertyValue(string $propertyName): mixed
    {
        $classData = $this->resolveCurrentClassData();

        if (null === $classData) {
            return null;
        }

        if (!array_key_exists($propertyName, $classData->properties)) {
            return null;
        }

        return $classData->properties[$propertyName] ?? null;
    }

    public function hasFillable(): bool
    {
        if (!$this->scope->isClassCall()) {
            return false;
        }

        return $this->hasProperty('fillable');
    }

    public function guardedIsEmptyArray(): bool
    {
        return [] === $this->getPropertyValue('guarded');
    }

    public function hasMassAssignmentProtection(): bool
    {
        $guarded = $this->getPropertyValue('guarded');

        if (is_array($guarded) && [] !== $guarded) {
            return true;
        }

        $fillable = $this->getPropertyValue('fillable');

        if (null === $fillable) {
            return false;
        }

        if ([] === $fillable) {
            return true;
        }

        return is_array($fillable) && !Selector::containsWildcardSelection($fillable);
    }

    public function fillableHasWildcardSelection(): bool
    {
        $fillable = $this->getPropertyValue('fillable');

        return is_array($fillable) && Selector::containsWildcardSelection($fillable);
    }

    public function isModelClass(): bool
    {
        $classData = $this->resolveCurrentClassData();

        if (!$classData instanceof ClassDataDto) {
            return false;
        }

        return in_array($classData->parentClass, self::LARAVEL_MODEL_CLASS, true);
    }

    public function isModelWriteMethodCall(): bool
    {
        if (!$this->isModelClass()) {
            return false;
        }

        $methodNameCall = $this->scope->nameAsString();

        return in_array(mb_strtolower((string)$methodNameCall), self::STATIC_SINK_METHODS, true);
    }

    private function resolveCurrentClassData(): ?ClassDataDto
    {
        $literalClass = $this->scope->classAsString();
        $resolvedClass = null !== $literalClass
            ? $this->resolver->resolveClassName($literalClass)
            : $this->scope->resolveReceiverClass($this->resolver);

        if (null === $resolvedClass) {
            return null;
        }

        $className = $this->resolver->resolveClassName($resolvedClass);

        return $this->projectDataFlowIndex->getClassData($className);
    }
}
