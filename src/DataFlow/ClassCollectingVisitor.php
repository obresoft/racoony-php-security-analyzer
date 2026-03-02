<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

use Obresoft\Racoony\Support\AttributeExtractor;
use PhpParser\Node;
use PhpParser\Node\Expr\Array_ as ArrayExpr;
use PhpParser\Node\Scalar\String_ as StringScalar;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Property;
use PhpParser\NodeVisitorAbstract;

use function is_string;

/**
 *
 * [
 *   'App\\Foo\\Bar' => [
 *     'parent' => 'App\\Foo\\BaseBar'|null,
 *     'interfaces' => list<string>,
 *     'own' => list<string>,
 *     'properties' => array<string, mixed>,
 *     'phpAttributes' => array<string, mixed>,
 *   ],
 * ]
 */
final class ClassCollectingVisitor extends NodeVisitorAbstract
{
    /**
     * @var array<string, array<string, mixed>>
     */
    private array $rawClassData = [];

    public function enterNode(Node $node): ?int
    {
        if (!$node instanceof Class_) {
            return null;
        }

        $fullyQualifiedClassName = $node->namespacedName?->toString();
        if (!is_string($fullyQualifiedClassName) || '' === $fullyQualifiedClassName) {
            return null;
        }

        $parentClassName = null;
        if (null !== $node->extends) {
            $parentClassName = $node->extends->getAttribute('resolvedName')?->toString()
                ?? $node->extends->toString();
        }

        $implementedInterfaces = [];
        foreach ($node->implements as $implementedInterface) {
            $implementedInterfaces[] = $implementedInterface->getAttribute('resolvedName')?->toString()
                ?? $implementedInterface->toString();
        }

        $ownMethodNames = [];
        foreach ($node->getMethods() as $methodNode) {
            $ownMethodNames[] = $methodNode->name->toString();
        }

        $this->rawClassData[$fullyQualifiedClassName] = [
            'parent' => $parentClassName,
            'interfaces' => $implementedInterfaces,
            'own' => $ownMethodNames,
            'properties' => self::extractClassProperties($node),
            'phpAttributes' => AttributeExtractor::extractFromClass($node),
        ];

        return null;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    public function getCollected(): array
    {
        return $this->rawClassData;
    }

    /**
     * @return array<string, mixed>
     */
    private static function extractClassProperties(Class_ $classNode): array
    {
        $properties = [];

        foreach ($classNode->stmts as $statement) {
            if (!$statement instanceof Property) {
                continue;
            }

            foreach ($statement->props as $propertyProperty) {
                $propertyName = $propertyProperty->name->toString();
                $defaultValueNode = $propertyProperty->default;

                if ($defaultValueNode instanceof StringScalar) {
                    $properties[$propertyName] = $defaultValueNode->value;

                    continue;
                }

                if (!$defaultValueNode instanceof ArrayExpr) {
                    continue;
                }

                if ([] === $defaultValueNode->items) {
                    $properties[$propertyName] = [];

                    continue;
                }

                $stringValues = [];

                foreach ($defaultValueNode->items as $item) {
                    if (null === $item || !$item->value instanceof StringScalar) {
                        continue;
                    }

                    $stringValues[] = $item->value->value;
                }

                if ([] === $stringValues) {
                    continue;
                }

                $properties[$propertyName] = $stringValues;
            }
        }

        return $properties;
    }
}
