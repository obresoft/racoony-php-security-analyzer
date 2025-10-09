<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

final readonly class ChainStep
{
    public function __construct(
        public string $type,
        public string $caller,
        public string $member,
        public int $line,
    ) {}
}
