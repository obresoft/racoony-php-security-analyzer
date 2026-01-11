<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command\Reporting;

use Obresoft\Racoony\Insight\Insight;
use Symfony\Component\Console\Output\OutputInterface;

final class JsonReport implements Report
{
    public function render(array $insights, OutputInterface $output): void
    {
        $payload = array_map(
            static fn (Insight $insight): array => [
                'file' => $insight->getFile(),
                'line' => $insight->getLine(),
                'severity' => $insight->getSeverity(),
                'type' => $insight->getType(),
                'message' => $insight->getMessage(),
            ],
            $insights,
        );

        $output->writeln(json_encode($payload, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));
    }
}
