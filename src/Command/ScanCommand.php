<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command;

use ArrayIterator;
use Obresoft\Racoony\CodeScanner\ASTFileScannerFactory;
use Obresoft\Racoony\Command\Reporting\JsonReport;
use Obresoft\Racoony\Command\Reporting\ReportBuilder;
use Obresoft\Racoony\Command\Reporting\TableReport;
use Obresoft\Racoony\Config\Config;
use Obresoft\Racoony\FileReader;
use Obresoft\Racoony\ScanRunner;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Finder\Finder;

use function count;
use function sprintf;

#[AsCommand(name: 'scan', description: 'Scan Project for Security Issues')]
final class ScanCommand extends Command
{
    private const string NAME = 'scan';

    private ReportBuilder $reportBuilder;

    public function __construct(private readonly Config $config)
    {
        parent::__construct(self::NAME);
        $this->reportBuilder = new ReportBuilder([
            'table' => new TableReport(),
            'json' => new JsonReport(),
            // 'sarif' => new SarifReport(),
        ]);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln(sprintf(
            '<bg=green;fg=white;>%s</>',
            'Scan project for security Issues has been started',
        ));

        $finder = Finder::create()
            ->in($this->config->getPath())
            ->append([__FILE__])
            ->exclude(
                ['vendor', 'tests', 'database', 'storage', 'cache', 'samples', 'docs', 'node_modules', '.git', '.svn'],
            )
            ->files();

        $files = new ArrayIterator(iterator_to_array($finder));
        $scanner = ASTFileScannerFactory::create(new FileReader(), $this->config->getApplication());

        $insights = (new ScanRunner(
            $files,
            $scanner,
            $this->config->getRules(),
        ))->run();

        if ([] === $insights) {
            $output->writeln('<info>No vulnerabilities found 🎉</info>');

            return Command::SUCCESS;
        }

        $output->writeln('');
        $output->writeln('<bg=red;fg=white> ⚠ Vulnerabilities Found </>');
        $output->writeln('');

        $needToFail = false;

        foreach ($insights as $insight) {
            if (!$needToFail) {
                $needToFail = $this->config->getFailOn()->isAtLeast($insight->getSeverity());
            }
        }

        $reportFormat = (string)$input->getOption('format');

        $report = $this->reportBuilder->build($reportFormat);
        $report->render($insights, $output);

        $output->writeln('');
        $output->writeln(sprintf(
            '<bg=yellow;fg=black> %d potential issue(s) found. </>',
            count($insights),
        ));

        return $needToFail ? Command::FAILURE : Command::SUCCESS;
    }

    protected function configure(): void
    {
        $this
            ->setName(self::NAME)
            ->addOption(
                'format',
                null,
                InputOption::VALUE_REQUIRED,
                'Output format (table, json, sarif)',
                'table',
            );
    }
}
