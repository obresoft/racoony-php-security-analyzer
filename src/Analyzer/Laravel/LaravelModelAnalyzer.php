<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Laravel;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Property;
use RuntimeException;

use function in_array;

final class LaravelModelAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    private const array LARAVEL_MODEL_CLASS = ['Illuminate\Database\Eloquent\Model', 'Illuminate\Foundation\Auth\User'];

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

    public function isLaravelModel(): bool
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

    public function hasFillable(): bool
    {
        $node = $this->scope->node();
        if (!$node instanceof Class_) {
            return false;
        }

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Property) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() === 'fillable') {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public function hasGuarded(): bool
    {
        $node = $this->scope->node();
        if (!$node instanceof Class_) {
            return false;
        }

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Property) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() === 'guarded') {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public function guardedIsEmptyArray(): bool
    {
        $array = $this->guardedArrayItems();

        return $array instanceof Array_ && count($array->items) === 0;
    }

    public function guardedArrayItems(): ?Array_
    {
        $node = $this->scope->node();
        if (!$node instanceof Class_) {
            return null;
        }

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Property) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() !== 'guarded') {
                        continue;
                    }
                    $default = $prop->default;
                    if ($default instanceof Array_) {
                        return $default;
                    }
                    return null;
                }
            }
        }

        return null;
    }

    public function hasFillableOrGuarded(): bool
    {
        $node = $this->scope->node();
        if (!$node instanceof Class_) {
            return false;
        }

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Property) {
                foreach ($stmt->props as $prop) {
                    if ('fillable' === $prop->name->toString()) {
                        return true;
                    }

                    if ('guarded' === $prop->name->toString()) {
                        $default = $prop->default;

                        if ($default instanceof Array_ && [] !== $default->items) {
                            return true;
                        }

                        if ($default instanceof Array_) {
                            foreach ($default->items as $item) {
                                if ($item->value instanceof String_ && '*' === $item->value->value) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    public function getFillableLine(): ?int
    {
        $node = $this->scope->node();
        if (!$node instanceof Class_) {
            return null;
        }

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Property) {
                foreach ($stmt->props as $prop) {
                    if ('fillable' === $prop->name->toString()) {
                        return $prop->getStartLine();
                    }
                }
            }
        }

        return null;
    }

    public function getGuardedLine(): ?int
    {
        $node = $this->scope->node();
        if (!$node instanceof Class_) {
            return null;
        }

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Property) {
                foreach ($stmt->props as $prop) {
                    if ('guarded' === $prop->name->toString()) {
                        return $prop->getStartLine();
                    }
                }
            }
        }

        return null;
    }

    public function isModelClass(): bool
    {
        $literalClass = $this->scope->classAsString();
        $resolvedClass = null !== $literalClass
            ? $this->resolver->resolveClassName($literalClass)
            : $this->scope->resolveReceiverClass($this->resolver);

        if (null === $resolvedClass) {
            return false;
        }

        $className = $this->resolver->resolveClassName($resolvedClass);
        $findClassData = $this->projectDataFlowIndex->getClassData($className);

        if (null === $findClassData) {
            return false;
        }

        return in_array($findClassData->parentClass, self::LARAVEL_MODEL_CLASS, true);
    }

    public function isModelWriteMethodCall(): bool
    {
        if (!$this->isModelClass()) {
            return false;
        }

        $methodNameCall = $this->scope->nameAsString();

        return in_array(mb_strtolower($methodNameCall), self::STATIC_SINK_METHODS, true);
    }
}