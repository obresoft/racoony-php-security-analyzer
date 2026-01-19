<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use JsonException;
use Obresoft\Racoony\Insight\Insight;

final class InsightCollector
{
    /** @var array<string, Insight> */
    private array $insights = [];

    /**
     * @throws JsonException
     */
    public function add(Insight $insight): void
    {
        $this->insights[$this->hash($insight)] = $insight;
    }

    /**
     * @return list<Insight>
     */
    public function all(): array
    {
        return array_values($this->insights);
    }

    public function reset(): void
    {
        $this->insights = [];
    }

    private function hash(Insight $insight): string
    {
        return hash('sha256', implode('|', [
            $insight->getFile(),
            (string)$insight->getLine(),
            $insight->getSeverity(),
            $insight->getMessage(),
        ]));
    }
}
