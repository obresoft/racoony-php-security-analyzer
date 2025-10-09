<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

use PhpParser\ErrorHandler\Throwing;
use PhpParser\Node;
use PhpParser\Node\Stmt\Class_;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;
use SplFileInfo;

use function array_key_exists;
use function is_array;
use function is_string;

final class ProjectDataFlowBuilder
{
    /**
     * @param list<SplFileInfo> $files
     */
    public function build(array $files): ProjectDataFlowIndex
    {
        $parser = (new ParserFactory())->createForVersion(PhpVersion::fromString('8.3'));
        $errorHandler = new Throwing();
        $index = new ProjectDataFlowIndex();

        $raw = [];

        foreach ($files as $file) {
            $code = @file_get_contents($file->getRealPath());
            if (false === $code) {
                continue;
            }
            $stmts = $parser->parse($code, $errorHandler) ?? [];

            $traverser = new NodeTraverser();
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

            $index->addClassData(new ClassDataDto(
                class: $fqcn,
                parentClass: $meta['parent'],
                implementedInterfaces: $meta['interfaces'],
                ownMethodNames: $meta['own'],
                inheritedMethods: $inherited,
            ));
        }

        return $index;
    }

    /** @param array<Node> $stmts @return iterable<Class_> */
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

    /** @param list<string> $values @return array<string,true> */
    private function toSet(array $values): array
    {
        $set = [];
        foreach ($values as $v) {
            $set[$v] = true;
        }

        return $set;
    }
}
