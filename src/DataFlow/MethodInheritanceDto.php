<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

final class MethodInheritanceDto
{
    public function __construct(
        public readonly string $methodName,
        public readonly string $declaredInClassFqcn,
    ) {}
}
