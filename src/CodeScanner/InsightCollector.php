<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use Obresoft\Racoony\Insight\Insight;

final class InsightCollector
{
    /** @var list<Insight> */
    private array $insights = [];

    public function add(Insight $insight): void
    {
        $this->insights[] = $insight;
    }

    /**
     * @return list<Insight>
     */
    public function all(): array
    {
        return $this->insights;
    }

    public function reset(): void
    {
        $this->insights = [];
    }
}
