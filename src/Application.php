<?php

declare(strict_types=1);

namespace Obresoft\Racoony;

use Obresoft\Racoony\Command\ScanCommand;
use Obresoft\Racoony\Command\ScanPackageCommand;
use Obresoft\Racoony\Config\Config;
use Obresoft\Racoony\Config\ConfigurationResolver;
use Obresoft\Racoony\Infrastructure\Downloader\GitHub\GitHubZipDownloader;
use Symfony\Component\Console\Application as BaseApplication;

final class Application extends BaseApplication
{
    public const string NAME = 'Racoony';

    public const string VERSION = '0.0.0';

    private readonly Config $config;

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);

        $configResolver = new ConfigurationResolver();
        $this->config = $configResolver->getConfig();
        $this->add(new ScanCommand($this->config));
        $this->add(new ScanPackageCommand(new GitHubZipDownloader()));
    }
}
