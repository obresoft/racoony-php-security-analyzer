<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver\Laravel;

use Obresoft\Racoony\DataFlow\ClassDataDto;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;
use Obresoft\Racoony\Resolver\MetadataResolver;
use Obresoft\Racoony\Resolver\TableNameResolver;

final readonly class LaravelMetadataResolvers implements MetadataResolver
{
    public function __construct(
        /** @var list<TableNameResolver> */
        public array $tables = [],
    ) {}

    public function resolveAll(ClassDataDto $classData, array $meta, ProjectDataFlowIndex $index): void
    {
        foreach ($this->tables as $resolver) {
            $tableName = $resolver->resolve($classData, $meta);
            if ($tableName) {
                $index->associateTableWithClass($tableName, $classData->class);

                break;
            }
        }
    }
}
