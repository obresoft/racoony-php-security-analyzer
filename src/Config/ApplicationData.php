<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Config;

final readonly class ApplicationData
{
    public function __construct(
        public string $frameworkName,
        public string $frameworkVersion,
    ) {}
}
