<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Insight;

interface Insight
{
    public function getFile(): string;

    public function getType(): string;

    public function getMessage(): string;

    public function getSeverity(): string;

    public function getLine(): int;
}
