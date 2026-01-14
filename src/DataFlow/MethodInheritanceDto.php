<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

final readonly class MethodInheritanceDto
{
    public function __construct(
        public string $methodName,
        public string $declaredInClassFqcn,
    ) {}
}
