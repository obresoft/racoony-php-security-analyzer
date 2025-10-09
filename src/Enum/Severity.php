<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Enum;

enum Severity: string
{
    case HIGH = 'HIGH';
    case CRITICAL = 'CRITICAL';
    case LOW = 'LOW';
    case MEDIUM = 'MEDIUM';
}
