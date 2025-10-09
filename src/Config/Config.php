<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Config;

use Obresoft\Racoony\Rule\Rule;

interface Config
{
    public function setPath(string $path): self;

    /** @return list<string> */
    public function getPath(): array;

    /**
     * @param array<int, string> $rules
     */
    public function setRules(array $rules): self;

    /**
     * @return list<class-string<Rule>>
     */
    public function getRules(): array;

    public function setApplication(ApplicationData $application): self;

    public function getApplication(): ?ApplicationData;
}
