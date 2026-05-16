<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command\Reporting;

use Symfony\Component\Console\Output\OutputInterface;

use function count;
use function in_array;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

final class TableReport implements Report
{
    private const string SEPARATOR = '────────────────────────────────────────────────────────────';

    private const array HIGH_SEVERITIES = ['HIGH', 'CRITICAL'];

    public function render(array $insights, OutputInterface $output): void
    {
        if ([] === $insights) {
            $output->writeln('<info>No vulnerabilities found 🎉</info>');

            return;
        }

        $lastIndex = count($insights) - 1;

        foreach ($insights as $i => $insight) {
            $filePath = $this->getRelativePath($insight->getFile());
            $severityLabel = $this->formatSeverityLabel($insight->getSeverity());

            $output->writeln(sprintf('%s %s: %s', $severityLabel, $insight->getType(), $insight->getMessage()));
            $output->writeln(sprintf('File: %s:%d', $filePath, $insight->getLine()));
            $output->writeln('');

            if ($i < $lastIndex) {
                $output->writeln(self::SEPARATOR);
                $output->writeln('');
            }
        }
    }

    private function formatSeverityLabel(string $severity): string
    {
        $label = sprintf('[%s]', $severity);

        if (in_array($severity, self::HIGH_SEVERITIES, true)) {
            return sprintf('<fg=red>%s</>', $label);
        }

        return $label;
    }

    private function getRelativePath(string $fullPath): string
    {
        $projectRoot = (string)getcwd();

        if (str_starts_with($fullPath, $projectRoot)) {
            return substr($fullPath, strlen($projectRoot) + 1);
        }

        return $fullPath;
    }
}
