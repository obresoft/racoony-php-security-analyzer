<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS)]
final class SensitiveFieldsAttribute
{
    public function __construct(private readonly array $fields) {}

    public function getFields(): array
    {
        return $this->fields;
    }
}
