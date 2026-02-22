<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver;

use Obresoft\Racoony\DataFlow\ClassDataDto;

interface TableNameResolver
{
    /**
     * @param array $meta Current gathered metadata (parents, interfaces, etc)
     */
    public function resolve(ClassDataDto $classDataDto, array $meta): ?string;
}
