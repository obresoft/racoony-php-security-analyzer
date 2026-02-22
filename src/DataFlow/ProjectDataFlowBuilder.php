<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

use Obresoft\Racoony\Resolver\MetadataResolver;
use Obresoft\Racoony\SourceCodeProvider;
use Obresoft\Racoony\Support\AttributeExtractor;
use PhpParser\ErrorHandler\Throwing;
use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Property;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;
use SplFileInfo;

use function array_key_exists;
use function is_array;
use function is_string;

final readonly class ProjectDataFlowBuilder
{
    public function __construct(
        private SourceCodeProvider $reader,
        /** @var list<MetadataResolver> */
        private array $frameworkResolvers = [],
    ) {}

    /**
     * @param list<SplFileInfo> $files
     */
    public function build(array $files): ProjectDataFlowIndex
    {
        $parser = (new ParserFactory())->createForVersion(PhpVersion::fromString('8.3'));
        $errorHandler = new Throwing();
        $index = new ProjectDataFlowIndex();
        $traverser = new NodeTraverser();
        $raw = [];

        foreach ($files as $file) {
            $path = $file->getRealPath();

            if (!is_string($path)) {
                continue;
            }

            $code = $this->reader->read($path);
            $stmts = $parser->parse($code, $errorHandler) ?? [];

            $traverser->addVisitor(new NameResolver(null, [
                'preserveOriginalNames' => true,
                'replaceNodes' => false,
            ]));

            $resolved = $traverser->traverse($stmts);

            foreach ($this->yieldClassNodes($resolved) as $classNode) {
                $fqcn = $classNode->namespacedName?->toString();
                if (!is_string($fqcn)) {
                    continue;
                }

                $parent = null;
                if (null !== $classNode->extends) {
                    $parent = $classNode->extends->getAttribute('resolvedName')?->toString()
                        ?? $classNode->extends->toString();
                }

                $interfaces = [];
                foreach ($classNode->implements as $impl) {
                    $interfaces[] = $impl->getAttribute('resolvedName')?->toString()
                        ?? $impl->toString();
                }

                $own = [];
                foreach ($classNode->getMethods() as $m) {
                    $own[] = $m->name->toString();
                }

                $raw[$fqcn] = [
                    'parent' => $parent,
                    'interfaces' => $interfaces,
                    'own' => $own,
                    'properties' => $this->extractClassProperties($classNode),
                    'propertyDefaults' => $this->extractPropertyDefaults($classNode),
                    'phpAttributes' => AttributeExtractor::extractFromClass($classNode),
                ];
            }
        }

        foreach ($raw as $fqcn => $meta) {
            $inherited = [];
            $childOwn = $this->toSet($meta['own']);
            $visited = [];
            $parent = $meta['parent'];

            while (null !== $parent) {
                if (isset($visited[$parent])) {
                    break;
                }

                $visited[$parent] = true;

                if (!array_key_exists($parent, $raw)) {
                    break;
                }

                foreach ($raw[$parent]['own'] as $methodName) {
                    if (!isset($childOwn[$methodName])) {
                        $inherited[] = new MethodInheritanceDto($methodName, $parent);
                    }
                }

                $parent = $raw[$parent]['parent'];
            }

            $classData = new ClassDataDto(
                class: $fqcn,
                parentClass: $meta['parent'],
                implementedInterfaces: $meta['interfaces'],
                ownMethodNames: $meta['own'],
                inheritedMethods: $inherited,
                properties: $meta['properties'],
                classAttributes: $meta['phpAttributes'],
            );

            $index->addClassData($classData);

            foreach ($this->frameworkResolvers as $frameworkResolver) {
                $frameworkResolver->resolveAll($classData, $meta, $index);
            }
        }

        return $index;
    }

    /**
     * @param array<Node> $stmts
     * @return iterable<Class_>
     */
    private function yieldClassNodes(array $stmts): iterable
    {
        $stack = $stmts;
        while ([] !== $stack) {
            /** @var Node $node */
            $node = array_pop($stack);
            if ($node instanceof Class_) {
                yield $node;
            }

            foreach ($node->getSubNodeNames() as $name) {
                $child = $node->{$name} ?? null;
                if ($child instanceof Node) {
                    $stack[] = $child;
                } elseif (is_array($child)) {
                    foreach ($child as $elem) {
                        if ($elem instanceof Node) {
                            $stack[] = $elem;
                        }
                    }
                }
            }
        }
    }

    /**
     * @param list<string> $values
     * @return array<string,true>
     */
    private function toSet(array $values): array
    {
        $set = [];
        foreach ($values as $v) {
            $set[$v] = true;
        }

        return $set;
    }

    private function extractClassProperties(Class_ $classNode): array
    {
        $attributes = [];

        foreach ($classNode->stmts as $statement) {
            if (!$statement instanceof Property) {
                continue;
            }

            foreach ($statement->props as $propertyProperty) {
                $default = $propertyProperty->default;

                if ($default instanceof String_) {
                    $attributes[$propertyProperty->name->toString()] = $default->value;

                    continue;
                }

                if (!$default instanceof Array_) {
                    continue;
                }

                if ([] === $default->items) {
                    $attributes[$propertyProperty->name->toString()] = [];

                    continue;
                }

                $values = [];

                foreach ($default->items as $item) {
                    if (null === $item) {
                        continue;
                    }

                    if (!$item->value instanceof String_) {
                        continue;
                    }

                    $values[] = $item->value->value;
                }

                if ([] === $values) {
                    continue;
                }

                $attributes[$propertyProperty->name->toString()] = $values;
            }
        }

        return $attributes;
    }

    private function extractPropertyDefaults(Class_ $classNode): array
    {
        $defaults = [];

        foreach ($classNode->stmts as $statement) {
            if (!$statement instanceof Property) {
                continue;
            }

            foreach ($statement->props as $property) {
                $name = $property->name->toString();
                $valueNode = $property->default;

                if ($valueNode instanceof String_) {
                    $defaults[$name] = $valueNode->value;
                } elseif ($valueNode instanceof Array_) {
                    $defaults[$name] = array_map(
                        static fn ($item) => $item->value instanceof String_ ? $item->value->value : null,
                        $valueNode->items,
                    );
                }
            }
        }

        return $defaults;
    }
}
