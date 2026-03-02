<?php

declare(strict_types=1);

use Obresoft\Racoony\CodeScanner\ASTFileScanner;
use Obresoft\Racoony\CodeScanner\ASTFileScannerFactory;
use Obresoft\Racoony\Command\Reporting\JsonReport;
use Obresoft\Racoony\Command\Reporting\ReportBuilder;
use Obresoft\Racoony\Command\Reporting\TableReport;
use Obresoft\Racoony\Config\Config;
use Obresoft\Racoony\Config\ConfigurationResolver;
use Obresoft\Racoony\DataFlow\ProjectDataFlowBuilder;
use Obresoft\Racoony\DataFlow\ProjectDataFlowBuilderFactory;
use Obresoft\Racoony\FileReader;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Obresoft\Racoony\Infrastructure\Downloader\ZipDownloader;
use Obresoft\Racoony\Infrastructure\Downloader\GitHub\GitHubZipDownloader;
use Symfony\Component\Filesystem\Filesystem;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;

return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->public();

    $services->load('Obresoft\\Racoony\\Command\\', __DIR__ . '/../src/Command/*');
    $services->load('Obresoft\\Racoony\\Rule\\', __DIR__ . '/../src/Rule/*');

    $services->set(ConfigurationResolver::class);
    $services->set(Config::class)
        ->factory([service(ConfigurationResolver::class), 'getConfig']);

    $services->set(FileReader::class);
    $services->set(TableReport::class);
    $services->set(JsonReport::class);

    $services->set(ReportBuilder::class)
        ->args([[
            'table' => service(TableReport::class),
            'json' => service(JsonReport::class),
        ]]);

    $services->set(ASTFileScanner::class)
        ->factory([ASTFileScannerFactory::class, 'create'])
        ->args([
            service(FileReader::class),
            inline_service('object')
                ->factory([service(Config::class), 'getApplication'])
        ]);

    $services->set(ProjectDataFlowBuilder::class)
        ->factory([ProjectDataFlowBuilderFactory::class, 'create'])
        ->args([service(FileReader::class)]);

    $services->set(Filesystem::class);

    $services->set(ZipDownloader::class, GitHubZipDownloader::class);
    $services->set(GitHubZipDownloader::class);
};