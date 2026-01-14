<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Node;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use PhpParser\Node\Attribute;

final class AttributeAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    public function __construct(
        protected Scope $scope,
    ) {}

    public function isAttribute(): bool
    {
        return $this->scope->node() instanceof Attribute;
    }

    public function getFullyQualifiedName(): string
    {
        $node = $this->scope->node();

        if (!$node instanceof Attribute) {
            return '';
        }

        $nameNode = $node->getAttribute('resolvedName') ?? $node->name;

        return ltrim((string)$nameNode->toString(), '\\');
    }

    public function getShortName(): string
    {
        $fullyQualified = $this->getFullyQualifiedName();

        if ('' === $fullyQualified) {
            return '';
        }

        $pos = strrpos($fullyQualified, '\\');

        return false === $pos ? $fullyQualified : substr($fullyQualified, $pos + 1);
    }

    public function matchesName(string $expectedName): bool
    {
        $normalizedExpectedName = ltrim($expectedName, '\\');

        $fullyQualifiedName = $this->getFullyQualifiedName();
        $shortName = $this->getShortName();

        return ('' !== $fullyQualifiedName && 0 === strcasecmp($fullyQualifiedName, $normalizedExpectedName))
            || ('' !== $shortName && 0 === strcasecmp($shortName, $normalizedExpectedName));
    }

    /**
     * @return list<Scope>
     */
    public function getArgumentsAsScopes(): array
    {
        $node = $this->scope->node();

        if (!$node instanceof Attribute) {
            return [];
        }

        $argumentScopes = [];

        foreach ($node->args as $arg) {
            $argumentScopes[] = $this->scope->withNode($arg->value);
        }

        return $argumentScopes;
    }
}
