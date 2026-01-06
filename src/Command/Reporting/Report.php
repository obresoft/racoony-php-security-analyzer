<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command\Reporting;

use Symfony\Component\Console\Output\OutputInterface;

interface Report
{
    public function render(array $insights, OutputInterface $output): void;
}
