<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command;

use Obresoft\Racoony\Infrastructure\Downloader\ZipDownloader;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Filesystem\Filesystem;

use function is_string;

#[AsCommand(name: 'scan:package', description: 'Scan GitHub Repository for Security Issues')]
final class ScanPackageCommand extends Command
{
    public function __construct(
        private readonly ZipDownloader $zipDownloader,
        private readonly Filesystem $filesystem,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'repo',
                null,
                InputOption::VALUE_REQUIRED,
                'GitHub repository URL (e.g., https://github.com/user/repo)',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $repoUrl = $input->getOption('repo');

        if (!$repoUrl || !is_string($repoUrl)) {
            $output->writeln('<error>Please provide a --repo option with GitHub URL</error>');

            return Command::FAILURE;
        }

        $output->writeln("<info>Downloading repository: {$repoUrl}...</info>");
        $tempDir = $this->zipDownloader->download($repoUrl);

        try {
            $command = $this->getApplication()?->find('scan');

            if (!$command) {
                $output->writeln('<error>Command "scan" not found.</error>');

                return Command::FAILURE;
            }

            return $command->run(new ArrayInput([]), $output);
        } finally {
            $this->filesystem->remove($tempDir);
        }
    }
}
