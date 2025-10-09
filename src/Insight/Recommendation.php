<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Insight;

final readonly class Recommendation implements Insight
{
    public function __construct(
        public string $file,
        public string $type,
        public string $message,
        public int $line,
        public string $severity = 'INFO',
    ) {}

    public function getFile(): string
    {
        return $this->file;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getMessage(): string
    {
        return $this->message;
    }

    public function getSeverity(): string
    {
        return $this->severity;
    }

    public function getLine(): int
    {
        return $this->line;
    }
}
