<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Config;

use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Rule\Rule;

interface Config
{
    /** @return list<string> */
    public function getPaths(): array;

    /**
     * @return array<class-string<Rule>>
     */
    public function getRules(): array;

    public function getApplication(): ?ApplicationData;

    public function getFailOn(): Severity;
}
