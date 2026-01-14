<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Node;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\Scope;
use PhpParser\Node;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;

use function is_object;

final readonly class ArrayAnalyzer implements AnalyzerInterface
{
    public function __construct(
        private Scope $scope,
    ) {}

    public function isArray(): bool
    {
        return $this->currentNode() instanceof Array_;
    }

    public function isArrayItem(): bool
    {
        return $this->currentNode() instanceof ArrayItem;
    }

    public function isArrayDimFetch(): bool
    {
        return $this->currentNode() instanceof ArrayDimFetch;
    }

    /**
     * @return array{}|list<ArrayItem>
     */
    public function arrayItems(): array
    {
        if (!$this->scope->arrayAnalyzer()->isArray()) {
            return [];
        }

        $node = $this->currentNode();

        return $node->items ?? [];
    }

    public function getFirstArrayItem(): ?ArrayItem
    {
        if (!$this->scope->arrayAnalyzer()->isArray()) {
            return null;
        }

        return $this->arrayItems()[0] ?? null;
    }

    /**
     * @return list<array{key: ?string, keyNode: ?Node, valueNode: Node}>
     */
    public function extractArrayKeyValuePairs(): array
    {
        $pairs = [];

        $node = $this->currentNode();
        if (!$node instanceof Array_) {
            return $pairs;
        }

        foreach ($node->items as $arrayItem) {
            if (!$arrayItem instanceof ArrayItem) {
                continue;
            }

            if ($arrayItem->unpack) {
                $pairs[] = [
                    'key' => null,
                    'keyNode' => null,
                    'valueNode' => $arrayItem->value,
                ];

                continue;
            }

            $resolvedKeyString = is_object($arrayItem->key) && property_exists($arrayItem->key, 'value')
                ? (string)($arrayItem->key->value)
                : null;

            $pairs[] = [
                'key' => $resolvedKeyString,
                'keyNode' => $arrayItem->key,
                'valueNode' => $arrayItem->value,
            ];
        }

        return $pairs;
    }

    /**
     * @return array<string, Scope>
     */
    public function extractArrayStringKeyToValueScopes(): array
    {
        $result = [];
        foreach ($this->extractArrayKeyValuePairs() as $pair) {
            if (null === $pair['key']) {
                continue;
            }

            if (null === $pair['valueNode']) {
                continue;
            }

            $result[$pair['key']] = $this->scope->withNode($pair['valueNode']);
        }

        return $result;
    }

    /**
     * @return iterable<Scope>
     */
    public function getArrayValueScopesRecursively(): iterable
    {
        $node = $this->currentNode();
        if (!$node instanceof Array_) {
            return;
        }

        foreach ($node->items as $arrayItem) {
            if (!$arrayItem instanceof ArrayItem) {
                continue;
            }

            $valueNode = $arrayItem->value;
            $valueScope = $this->scope->withNode($valueNode);
            yield $valueScope;

            if ($valueNode instanceof Array_) {
                $nestedHelper = new self($valueScope);
                yield from $nestedHelper->getArrayValueScopesRecursively();
            }
        }
    }

    private function currentNode(): Node
    {
        return $this->scope->node();
    }
}
