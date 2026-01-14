<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Node;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\Scope;
use PhpParser\Node\Attribute;
use PhpParser\Node\Param;

use function is_string;

final readonly class ParamAnalyzer implements AnalyzerInterface
{
    public function __construct(
        private Scope $scope,
    ) {}

    public function isParameter(): bool
    {
        return $this->scope->node() instanceof Param;
    }

    public function getParameterName(): string
    {
        $node = $this->scope->node();

        if (!$node instanceof Param) {
            return '';
        }

        return is_string($node->var->name) ? $node->var->name : '';
    }

    public function getAttributesAsScope(): array
    {
        $node = $this->scope->node();

        if (!$node instanceof Param) {
            return [];
        }

        $scopes = [];

        foreach ($node->attrGroups as $attributeGroup) {
            foreach ($attributeGroup->attrs as $attribute) {
                if ($attribute instanceof Attribute) {
                    $scopes[] = $this->scope->withNode($attribute);
                }
            }
        }

        return $scopes;
    }
}
