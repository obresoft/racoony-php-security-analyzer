<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

interface ProjectDataFlow
{
    public function getClassData(string $classFqcn): ?ClassDataDto;
}
