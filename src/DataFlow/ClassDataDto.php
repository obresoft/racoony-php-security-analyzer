<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

final class ClassDataDto
{
    /**
     * @param list<string> $implementedInterfaces
     * @param list<string> $ownMethodNames
     * @param list<MethodInheritanceDto> $inheritedMethods
     */
    public function __construct(
        public readonly string $class,
        public readonly ?string $parentClass,
        public readonly array $implementedInterfaces,
        public readonly array $ownMethodNames,
        public readonly array $inheritedMethods,
    ) {}
}
