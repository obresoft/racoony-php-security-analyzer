<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command\Reporting;

use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Output\OutputInterface;

final class TableReport implements Report
{
    public function render(array $insights, OutputInterface $output): void
    {
        if ([] === $insights) {
            $output->writeln('<info>No vulnerabilities found 🎉</info>');

            return;
        }

        $table = new Table($output);
        $table->setHeaders(['File', 'Line', 'Severity', 'Issue'])
            ->setColumnMaxWidth(3, 60);

        foreach ($insights as $insight) {
            $table->addRow([
                $insight->getFile(),
                (string)$insight->getLine(),
                $insight->getSeverity(),
                $insight->getMessage(),
            ]);
        }

        $table->render();
    }
}
