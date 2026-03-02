<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

use Obresoft\Racoony\Resolver\MetadataResolver;
use Obresoft\Racoony\SourceCodeProvider;
use PhpParser\Error;
use PhpParser\ErrorHandler\Throwing;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;
use SplFileInfo;

use function array_key_exists;
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

        $raw = [];

        foreach ($files as $file) {
            $realPath = $file->getRealPath();
            if (!is_string($realPath) || '' === $realPath) {
                continue;
            }

            try {
                $sourceCode = $this->reader->read($realPath);
                $statements = $parser->parse($sourceCode, $errorHandler) ?? [];

                $nodeTraverser = new NodeTraverser();
                $nodeTraverser->addVisitor(new NameResolver(null, [
                    'preserveOriginalNames' => true,
                    'replaceNodes' => false,
                ]));

                $collector = new ClassCollectingVisitor();
                $nodeTraverser->addVisitor($collector);

                $nodeTraverser->traverse($statements);

                $raw = array_merge($raw, $collector->getCollected());
            } catch (Error) {
                continue;
            }

            unset($sourceCode, $statements, $nodeTraverser, $collector);
        }

        foreach ($raw as $fqcn => $meta) {
            $inherited = [];
            $childOwn = array_flip($meta['own']);
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
}
