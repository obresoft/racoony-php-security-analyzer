<?php

declare(strict_types=1);

namespace Obresoft\Racoony;

interface SourceCodeProvider
{
    public function read(string $source): string;
}
