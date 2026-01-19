<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Support;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt\Class_;

use function is_int;
use function is_string;

final class AttributeExtractor
{
    public static function extractFromClass(Class_ $classNode): array
    {
        $attributes = [];

        foreach ($classNode->attrGroups as $group) {
            foreach ($group->attrs as $attribute) {
                $name = $attribute->name->getAttribute('resolvedName')
                    ?->toString()
                    ?? $attribute->name->toString();

                $attributes[$name] = self::extractArguments($attribute->args);
            }
        }

        return $attributes;
    }

    /**
     * @param list<Arg> $args
     * @return array<int|string, mixed>
     */
    private static function extractArguments(array $args): array
    {
        $result = [];

        foreach ($args as $arg) {
            $value = self::resolveValue($arg->value);
            if (null !== $arg->name) {
                $result[$arg->name->toString()] = $value;

                continue;
            }

            $result[] = $value;
        }

        return $result;
    }

    private static function resolveValue(Node $node): mixed
    {
        if ($node instanceof Scalar
        ) {
            return $node->value ?? null;
        }

        if ($node instanceof Array_) {
            return self::resolveArray($node);
        }

        return [];
    }

    /**
     * @return array<int|string, mixed>
     */
    private static function resolveArray(Array_ $array): array
    {
        $result = [];

        foreach ($array->items as $item) {
            if (!$item instanceof ArrayItem) {
                continue;
            }

            $value = $item->value ? self::resolveValue($item->value) : null;

            if (null === $item->key) {
                $result[] = $value;

                continue;
            }

            $key = self::resolveValue($item->key);

            if (is_string($key) || is_int($key)) {
                $result[$key] = $value;

                continue;
            }

            $result[] = $value;
        }

        return $result;
    }
}
