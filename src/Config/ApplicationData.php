<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Config;

final class ApplicationData
{
    public function __construct(
        public readonly string $frameworkName,
        public readonly string $frameworkVersion,
    ) {}
}
