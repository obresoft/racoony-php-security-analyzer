<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command;

use ArrayIterator;
use Obresoft\Racoony\CodeScanner\ASTFileScanner;
use Obresoft\Racoony\Command\Reporting\ReportBuilder;
use Obresoft\Racoony\Config\Config;
use Obresoft\Racoony\DataFlow\ProjectDataFlowBuilder;
use Obresoft\Racoony\ScanRunner;
use SplFileInfo;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Finder\Finder;

use function count;
use function sprintf;

#[AsCommand(name: 'scan', description: 'Scan Project for Security Issues')]
final class ScanCommand extends Command
{
    private const string NAME = 'scan';

    public function __construct(
        private readonly Config $config,
        private readonly ReportBuilder $reportBuilder,
        private readonly ASTFileScanner $scanner,
        private readonly ProjectDataFlowBuilder $dataFlowBuilder,
    ) {
        parent::__construct(self::NAME);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln(sprintf(
            '<bg=green;fg=white;>%s</>',
            'Scan project for security Issues has been started',
        ));

        $finder = Finder::create()
            ->in($this->config->getPaths())
            ->append([__FILE__])
            ->exclude(
                ['vendor', 'tests', 'database', 'storage', 'cache', 'samples', 'docs', 'node_modules', '.git', '.svn'],
            )
            ->files()
            ->name('*.php');

        $filesArray = iterator_to_array($finder);
        $files = new ArrayIterator($filesArray);
        $totalFiles = count($filesArray);

        $reportFormat = strtolower((string)$input->getOption('format'));

        $progressOutput = $output;

        if ('json' === $reportFormat && $output instanceof ConsoleOutputInterface) {
            $progressOutput = $output->getErrorOutput();
        }

        $progressBar = null;
        $onFileScanned = null;

        if ($progressOutput->isDecorated() && $input->isInteractive()) {
            $progressBar = new ProgressBar($progressOutput, $totalFiles);
            $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%%  %message%');
            $progressBar->setMessage('Scanning files...');
            $progressBar->start();

            $onFileScanned = static function (SplFileInfo $file) use ($progressBar): void {
                $progressBar->setMessage($file->getFilename());
                $progressBar->advance();
            };
        }

        try {
            $insights = (new ScanRunner(
                $files,
                $this->scanner,
                $this->config->getRules(),
                $this->dataFlowBuilder,
                $onFileScanned,
            ))->run();
        } finally {
            if ($progressBar instanceof ProgressBar) {
                $progressBar->finish();
                $progressOutput->writeln('');
            }
        }

        if ([] === $insights) {
            $output->writeln('<info>No vulnerabilities found 🎉</info>');

            return Command::SUCCESS;
        }

        $output->writeln(['', '<bg=red;fg=white> ⚠ Vulnerabilities Found </>', '']);

        $needToFail = false;
        foreach ($insights as $insight) {
            if (!$needToFail) {
                $needToFail = $this->config->getFailOn()->isAtLeast($insight->getSeverity());
            }
        }

        $this->reportBuilder->build($reportFormat)->render($insights, $output);

        $output->writeln(sprintf(
            "\n<bg=yellow;fg=black> %d potential issue(s) found. </>\n",
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
                'Output format (table, json)',
                'table',
            );
    }
}
