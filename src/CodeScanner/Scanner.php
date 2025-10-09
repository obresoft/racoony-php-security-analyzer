<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\Rule;

/**
 * @template T of Rule
 */
interface Scanner
{
    /**
     * @param T $rule
     * @return list<Insight>
     */
    public function scan(string $filePath, Rule $rule): array;
}
