<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

final readonly class ClassDataDto
{
    /**
     * @param list<string> $implementedInterfaces
     * @param list<string> $ownMethodNames
     * @param list<MethodInheritanceDto> $inheritedMethods
     */
    public function __construct(
        public string $class,
        public ?string $parentClass,
        public array $implementedInterfaces,
        public array $ownMethodNames,
        public array $inheritedMethods,
    ) {}
}
