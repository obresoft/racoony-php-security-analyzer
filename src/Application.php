<?php

declare(strict_types=1);

namespace Obresoft\Racoony;

use Obresoft\Racoony\Command\ScanCommand;
use Obresoft\Racoony\Command\ScanPackageCommand;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\Console\Application as BaseApplication;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

final class Application extends BaseApplication
{
    public const string NAME = 'Racoony';

    public const string VERSION = '0.1.0';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);

        $container = new ContainerBuilder();
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../config'));
        $loader->load('services.php');
        $container->compile();

        $this->addCommand($container->get(ScanCommand::class));
        $this->addCommand($container->get(ScanPackageCommand::class));
    }
}
