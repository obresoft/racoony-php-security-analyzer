<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\IntersectionType;
use PhpParser\Node\Name;
use PhpParser\Node\NullableType;
use PhpParser\Node\Param;
use PhpParser\Node\Stmt\Function_;
use PhpParser\Node\UnionType;
use SplObjectStorage;

use function is_array;
use function is_string;

final class FileIndex
{
    /** @var array<string, list<Assign>> */
    public array $assignmentsByVariable = [];

    /** @var array<string, list<Param>> */
    public array $parametersByVariable = [];

    /** @var array<string, list<string>> */
    public array $parameterTypesByVariable = [];

    /** @var array<string, Function_> */
    public array $functionByName = [];

    /** @var SplObjectStorage<Node, Node> */
    public SplObjectStorage $parent;

    /** @var SplObjectStorage<Node, true> */
    private SplObjectStorage $visited;

    /** @param list<Node> $roots */
    public function __construct(private readonly array $roots)
    {
        $this->parent = new SplObjectStorage();
        $this->visited = new SplObjectStorage();
        $this->build();
    }

    /** @return list<Assign> */
    public function getAssignments(string $variableName): array
    {
        return $this->assignmentsByVariable[$variableName] ?? [];
    }

    /** @return list<Param> */
    public function getParams(string $variableName): array
    {
        return $this->parametersByVariable[$variableName] ?? [];
    }

    /** @return list<string> */
    public function getParamTypes(string $variableName): array
    {
        return $this->parameterTypesByVariable[$variableName] ?? [];
    }

    public function findFunction(string $name): ?Function_
    {
        return $this->functionByName[$name] ?? null;
    }

    public function parentOf(Node $node): ?Node
    {
        return $this->parent[$node] ?? null;
    }

    private function build(): void
    {
        $walk = function (Node $node) use (&$walk): void {
            if (isset($this->visited[$node])) {
                return;
            }
            $this->visited[$node] = true;

            foreach ($node->getSubNodeNames() as $subNodeName) {
                $value = $node->{$subNodeName} ?? null;
                if ($value instanceof Node) {
                    $this->parent[$value] = $node;
                    $walk($value);
                } elseif (is_array($value)) {
                    foreach ($value as $child) {
                        if ($child instanceof Node) {
                            $this->parent[$child] = $node;
                            $walk($child);
                        }
                    }
                }
            }

            if (
                $node instanceof Assign
                && $node->var instanceof Variable
                && is_string($node->var->name)
            ) {
                $this->assignmentsByVariable[$node->var->name][] = $node;
            }

            if ($node instanceof Param && $node->var instanceof Variable && is_string($node->var->name)) {
                $varName = $node->var->name;
                $this->parametersByVariable[$varName][] = $node;

                $types = $this->normalizeTypeToStrings($node->type);
                if ([] !== $types) {
                    $existing = $this->parameterTypesByVariable[$varName] ?? [];
                    $this->parameterTypesByVariable[$varName] = array_values(
                        array_unique(array_merge($existing, $types)),
                    );
                }
            }

            if ($node instanceof Function_) {
                $this->functionByName[$node->name->toString()] = $node;
            }
        };

        foreach ($this->roots as $root) {
            $walk($root);
        }
    }

    /** @return list<string> */
    private function normalizeTypeToStrings(null|Identifier|IntersectionType|Name|NullableType|UnionType $type): array
    {
        if (null === $type) {
            return [];
        }

        if ($type instanceof Identifier) {
            return [$type->toString()];
        }

        if ($type instanceof Name) {
            return [$type->toString()];
        }

        if ($type instanceof NullableType) {
            return array_values(array_unique(array_merge(['null'], $this->normalizeTypeToStrings($type->type))));
        }

        if ($type instanceof UnionType) {
            $out = [];
            foreach ($type->types as $t) {
                $out = array_merge($out, $this->normalizeTypeToStrings($t));
            }

            return array_values(array_unique($out));
        }

        if ($type instanceof IntersectionType) {
            $out = [];
            foreach ($type->types as $t) {
                $out = array_merge($out, $this->normalizeTypeToStrings($t));
            }

            return array_values(array_unique($out));
        }

        return [];
    }
}
