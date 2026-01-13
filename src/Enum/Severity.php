<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Enum;

enum Severity: string
{
    case INFO = 'INFO';
    case LOW = 'LOW';
    case MEDIUM = 'MEDIUM';
    case HIGH = 'HIGH';
    case CRITICAL = 'CRITICAL';

    public function rank(): int
    {
        return match ($this) {
            self::INFO => 0,
            self::LOW => 1,
            self::MEDIUM => 2,
            self::HIGH => 3,
            self::CRITICAL => 4,
        };
    }

    public function isAtLeast(mixed $threshold): bool
    {
        $threshold = Severity::tryFrom($threshold) ?? Severity::LOW;

        return $this->rank() >= $threshold->rank();
    }
}
