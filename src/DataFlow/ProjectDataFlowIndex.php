<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

final class ProjectDataFlowIndex implements ProjectDataFlow
{
    /** @var array<string, ClassDataDto> */
    private array $classesByFqcn = [];

    public function addClassData(ClassDataDto $classData): void
    {
        $this->classesByFqcn[$classData->class] = $classData;
    }

    public function getClassData(string $classFqcn): ?ClassDataDto
    {
        return $this->classesByFqcn[$classFqcn] ?? null;
    }
}
