<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

final class ProjectDataFlowIndex implements ProjectDataFlow
{
    /** @var array<string, ClassDataDto> */
    private array $classesByFqcn = [];

    /** @var array<string, string> */
    private array $tableToFqcn = [];

    public function addClassData(ClassDataDto $classData): void
    {
        $this->classesByFqcn[$classData->class] = $classData;
    }

    public function getClassData(string $classFqcn): ?ClassDataDto
    {
        return $this->classesByFqcn[$classFqcn] ?? null;
    }

    public function associateTableWithClass(string $tableName, string $classFqcn): void
    {
        $this->tableToFqcn[$tableName] = $classFqcn;
    }

    public function getClassByTable(string $tableName): ?ClassDataDto
    {
        $fqcn = $this->tableToFqcn[$tableName] ?? null;

        if (!$fqcn) {
            return null;
        }

        return $this->getClassData($fqcn);
    }
}
