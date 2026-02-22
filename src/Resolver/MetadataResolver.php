<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver;

use Obresoft\Racoony\DataFlow\ClassDataDto;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;

interface MetadataResolver
{
    public function resolveAll(ClassDataDto $classData, array $meta, ProjectDataFlowIndex $index): void;
}
