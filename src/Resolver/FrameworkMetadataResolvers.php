<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver;

use Obresoft\Racoony\DataFlow\ClassDataDto;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;

final readonly class FrameworkMetadataResolvers implements MetadataResolver
{
    public function __construct(
        /** @var list<FrameworkDataResolver> */
        public array $resolvers = [],
    ) {}

    public function resolveAll(ClassDataDto $classData, array $meta, ProjectDataFlowIndex $index): void
    {
        foreach ($this->resolvers as $resolver) {
            $resolver->resolve($classData, $meta, $index);
        }
    }
}
