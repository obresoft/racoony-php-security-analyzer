<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver\Laravel;

use Doctrine\Inflector\InflectorFactory;
use Obresoft\Racoony\DataFlow\ClassDataDto;
use Obresoft\Racoony\Resolver\TableNameResolver;

use function in_array;
use function is_string;

final class LaravelEloquentTableResolver implements TableNameResolver
{
    public function resolve(ClassDataDto $classDataDto, array $meta): ?string
    {
        $propertyDefaults = $classDataDto->properties ?? [];

        $isEloquentModel = $this->isEloquentModel($classDataDto);

        if (!$isEloquentModel) {
            return null;
        }

        $tablePropertyValue = $propertyDefaults['table'] ?? null;

        if (is_string($tablePropertyValue) && '' !== $tablePropertyValue) {
            return $tablePropertyValue;
        }

        return $this->inferTableNameFromClass($classDataDto->class);
    }

    private function isEloquentModel(ClassDataDto $dto): bool
    {
        $eloquentClasses = [
            'Illuminate\Database\Eloquent\Model',
            'Illuminate\Foundation\Auth\User',
            'Illuminate\Database\Eloquent\Relations\Pivot',
        ];

        return in_array($dto->parentClass, $eloquentClasses, true);
    }

    private function inferTableNameFromClass(string $fullyQualifiedClassName): string
    {
        $parts = explode('\\', $fullyQualifiedClassName);
        $classBaseName = end($parts);
        $snake = strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', $classBaseName));

        return InflectorFactory::create()->build()->pluralize($snake);
    }
}
