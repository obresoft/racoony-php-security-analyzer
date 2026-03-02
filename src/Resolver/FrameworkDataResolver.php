<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver;

use Obresoft\Racoony\DataFlow\ClassDataDto;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;

interface FrameworkDataResolver
{
    public function resolve(ClassDataDto $classDataDto, array $meta, ProjectDataFlowIndex $projectDataFlowIndex): void;
}
