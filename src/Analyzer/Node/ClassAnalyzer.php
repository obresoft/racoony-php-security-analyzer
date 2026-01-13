<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Node;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayItem;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\UnaryMinus;
use PhpParser\Node\Expr\UnaryPlus;
use PhpParser\Node\Identifier;
use PhpParser\Node\IntersectionType;
use PhpParser\Node\Name;
use PhpParser\Node\NullableType;
use PhpParser\Node\Scalar\Encapsed;
use PhpParser\Node\Scalar\EncapsedStringPart;
use PhpParser\Node\Scalar\Float_;
use PhpParser\Node\Scalar\Int_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassConst;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Property;
use PhpParser\Node\Stmt\TraitUse;
use PhpParser\Node\UnionType;

use function count;
use function in_array;
use function is_scalar;

final class ClassAnalyzer
{
    public function analyzeClass(Class_ $class): array
    {
        $analysis = [
            'name' => $class->name?->toString(),
            'extends' => $class->extends?->toString(),
            'implements' => array_map(static fn ($i) => $i->toString(), $class->implements),
            'properties' => [],
            'methods' => [],
            'constants' => [],
            'traits' => [],
            'modifiers' => $this->getClassModifiers($class),
        ];

        foreach ($class->stmts as $stmt) {
            match (true) {
                $stmt instanceof Property => $this->analyzeProperty($stmt, $analysis),
                $stmt instanceof ClassMethod => $this->analyzeMethod($stmt, $analysis),
                $stmt instanceof ClassConst => $this->analyzeConstant($stmt, $analysis),
                $stmt instanceof TraitUse => $this->analyzeTrait($stmt, $analysis),
                default => null,
            };
        }

        return $analysis;
    }

    public function analyzeProperties(Class_ $classNode): array
    {
        $result = [];

        foreach ($classNode->getProperties() as $property) {
            if (!$property instanceof Property) {
                continue;
            }

            foreach ($property->props as $prop) {
                $result[] = [
                    'name' => $prop->name->toString(),
                    'type' => $property->type?->toString(),
                    'value' => $this->normalizeValue($prop->default),
                    'node' => $property,
                    'line' => $property->getStartLine(),
                ];
            }
        }

        return $result;
    }

    private function analyzeProperty(Property $property, array &$analysis): void
    {
        foreach ($property->props as $prop) {
            $analysis['properties'][] = [
                'name' => $prop->name->toString(),
                'visibility' => $this->getVisibility($property),
                'isStatic' => $property->isStatic(),
                'isReadonly' => $property->isReadonly(),
                'type' => $this->getTypeAsString($property->type),
                'defaultValue' => $this->getDefaultValue($prop->default),
                'docComment' => $property->getDocComment()?->getText(),
            ];
        }
    }

    private function getTypeAsString($type): ?string
    {
        if (null === $type) {
            return null;
        }

        if ($type instanceof Identifier) {
            return $type->toString();
        }

        if ($type instanceof Name) {
            return $type->toString();
        }

        if ($type instanceof NullableType) {
            return '?' . $this->getTypeAsString($type->type);
        }

        if ($type instanceof UnionType) {
            return implode('|', array_map($this->getTypeAsString(...), $type->types));
        }

        if ($type instanceof IntersectionType) {
            return implode('&', array_map($this->getTypeAsString(...), $type->types));
        }

        return null;
    }

    private function analyzeMethod(ClassMethod $method, array &$analysis): void
    {
        $analysis['methods'][] = [
            'name' => $method->name->toString(),
            'visibility' => $this->getVisibility($method),
            'isStatic' => $method->isStatic(),
            'isAbstract' => $method->isAbstract(),
            'isFinal' => $method->isFinal(),
            'returnType' => (static function ($type) {
                if (null === $type) {
                    return null;
                }

                if ($type instanceof NullableType) {
                    return '?' . ((method_exists($type->type, 'toString'))
                            ? $type->type->toString()
                            : (string)$type->type);
                }

                if ($type instanceof UnionType) {
                    return implode('|', array_map(static fn ($t) => method_exists($t, 'toString') ? $t->toString() : (string)$t, $type->types));
                }

                if ($type instanceof IntersectionType) {
                    return implode('&', array_map(static fn ($t) => method_exists($t, 'toString') ? $t->toString() : (string)$t, $type->types));
                }

                if (method_exists($type, 'toString')) {
                    return $type->toString();
                }

                return (string)$type;
            })($method->returnType),
            'parameters' => array_map(fn ($p) => [
                'name' => $p->var->name,
                'type' => (static function ($type) {
                    $toString = static function ($t) use (&$toString) {
                        if (null === $t) {
                            return null;
                        }

                        if ($t instanceof NullableType) {
                            return '?' . $toString($t->type);
                        }

                        if ($t instanceof UnionType) {
                            $parts = array_map(static fn ($x) => $toString($x), $t->types);
                            $hasNull = in_array('null', $parts, true);
                            $nonNull = array_values(array_filter($parts, static fn ($p) => null !== $p && 'null' !== $p));

                            if ($hasNull && 1 === count($nonNull)) {
                                return '?' . $nonNull[0];
                            }

                            return implode('|', $parts);
                        }

                        if ($t instanceof IntersectionType) {
                            $parts = array_map(static fn ($x) => $toString($x), $t->types);

                            return implode('&', $parts);
                        }

                        return method_exists($t, 'toString') ? $t->toString() : (string)$t;
                    };

                    return $toString($type);
                })($p->type),
                'hasDefault' => $p->default instanceof Expr,
                'defaultValue' => $this->getDefaultValue($p->default),
            ], $method->params),
            'docComment' => $method->getDocComment()?->getText(),
        ];
    }

    private function analyzeConstant(ClassConst $consts, array &$analysis): void
    {
        foreach ($consts->consts as $const) {
            $analysis['constants'][] = [
                'name' => $const->name->toString(),
                'value' => $this->getDefaultValue($const->value),
                'visibility' => $this->getVisibility($consts),
                'docComment' => $consts->getDocComment()?->getText(),
            ];
        }
    }

    private function analyzeTrait(TraitUse $traitUse, array &$analysis): void
    {
        foreach ($traitUse->traits as $trait) {
            $analysis['traits'][] = $trait->toString();
        }
    }

    private function getVisibility($node): string
    {
        if ($node->isPrivate()) {
            return 'private';
        }

        if ($node->isProtected()) {
            return 'protected';
        }

        return 'public';
    }

    private function getClassModifiers(Class_ $class): array
    {
        $modifiers = [];
        if ($class->isAbstract()) {
            $modifiers[] = 'abstract';
        }

        if ($class->isFinal()) {
            $modifiers[] = 'final';
        }

        if ($class->isReadonly()) {
            $modifiers[] = 'readonly';
        }

        return $modifiers;
    }

    private function getDefaultValue(?Node $node): mixed
    {
        if (!$node instanceof Node) {
            return null;
        }

        return match (true) {
            $node instanceof String_ => $node->value,
            $node instanceof Int_ => $node->value,
            $node instanceof Float_ => $node->value,
            $node instanceof Array_ => 'array(...)',
            default => 'complex_expression',
        };
    }

    /**
     * Recursively normalize any Node into a structured array with 'value' and 'node'.
     * For arrays: returns list of ['key' => <normalized>, 'value' => <normalized>, 'node' => ArrayItem].
     * For scalars: returns ['type' => 'string|int|float|bool|null', 'value' => <scalar>, 'node' => Node].
     * For ::class: returns ['type' => 'class_string', 'value' => 'App\\Foo\\Bar', 'node' => ClassConstFetch].
     * For complex expressions: returns ['type' => 'complex_expression', 'value' => null, 'node' => Node].
     */
    private function normalizeValue(?Node $node, int $depth = 0, int $maxDepth = 25): array
    {
        if (!$node instanceof Node) {
            return ['type' => 'null', 'value' => null, 'node' => null];
        }

        if ($depth > $maxDepth) {
            return ['type' => 'max_depth', 'value' => null, 'node' => $node];
        }

        // Scalars
        if ($node instanceof String_) {
            return ['type' => 'string', 'value' => $node->value, 'node' => $node];
        }

        if ($node instanceof Int_) {
            /** @var int $val */
            $val = $node->value;

            return ['type' => 'int', 'value' => $val, 'node' => $node];
        }

        if ($node instanceof Float_) {
            /** @var float $val */
            $val = $node->value;

            return ['type' => 'float', 'value' => $val, 'node' => $node];
        }

        // true/false/null
        if ($node instanceof ConstFetch) {
            $constName = strtolower($node->name->toString());
            if ('true' === $constName || 'false' === $constName) {
                return ['type' => 'bool', 'value' => 'true' === $constName, 'node' => $node];
            }

            if ('null' === $constName) {
                return ['type' => 'null', 'value' => null, 'node' => $node];
            }

            return ['type' => 'const', 'value' => $constName, 'node' => $node];
        }

        if ($node instanceof Encapsed) {
            $parts = [];
            foreach ($node->parts as $part) {
                if ($part instanceof EncapsedStringPart) {
                    $parts[] = $part->value;
                } elseif ($part instanceof String_) {
                    $parts[] = $part->value;
                } else {
                    return ['type' => 'complex_expression', 'value' => null, 'node' => $node];
                }
            }

            return ['type' => 'string', 'value' => implode('', $parts), 'node' => $node];
        }

        if ($node instanceof UnaryMinus || $node instanceof UnaryPlus) {
            $inner = $this->normalizeValue($node->expr, $depth + 1, $maxDepth);

            if (in_array($inner['type'], ['int', 'float'], true) && is_numeric($inner['value'])) {
                $val = $node instanceof UnaryMinus ? -1 * $inner['value'] : +1 * $inner['value'];

                return ['type' => $inner['type'], 'value' => $val, 'node' => $node];
            }

            return ['type' => 'complex_expression', 'value' => null, 'node' => $node];
        }

        if ($node instanceof Concat) {
            $left = $this->normalizeValue($node->left, $depth + 1, $maxDepth);
            $right = $this->normalizeValue($node->right, $depth + 1, $maxDepth);
            if (isset($left['value'], $right['value'])
                && is_scalar($left['value']) && is_scalar($right['value'])) {
                return [
                    'type' => 'string',
                    'value' => $left['value'] . $right['value'],
                    'node' => $node,
                    'left' => $left,
                    'right' => $right,
                ];
            }

            return [
                'type' => 'complex_expression',
                'value' => null,
                'node' => $node,
                'left' => $left,
                'right' => $right,
            ];
        }

        if ($node instanceof Identifier) {
            return ['type' => 'identifier', 'value' => $node->toString(), 'node' => $node];
        }

        if ($node instanceof Name) {
            return ['type' => 'name', 'value' => $node->toString(), 'node' => $node];
        }

        if ($node instanceof Array_) {
            $items = [];
            foreach ($node->items ?? [] as $item) {
                if (!$item instanceof ArrayItem) {
                    continue;
                }

                $items[] = [
                    'key' => $item->key instanceof Expr ? $this->normalizeValue(
                        $item->key,
                        $depth + 1,
                        $maxDepth,
                    ) : ['type' => 'null', 'value' => null, 'node' => null],
                    'value' => $this->normalizeValue($item->value, $depth + 1, $maxDepth),
                    'node' => $item,
                ];
            }

            return ['type' => 'array', 'value' => $items, 'node' => $node];
        }

        return ['type' => 'complex_expression', 'value' => null, 'node' => $node];
    }
}
