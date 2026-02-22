<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver\Dto;

final readonly class TableReferenceDto
{
    public function __construct(
        public string $tableName,
        public ?string $alias,
    ) {}
}
