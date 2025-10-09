<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Config;

use Obresoft\Racoony\Rule\RuleSet;

use const DIRECTORY_SEPARATOR;

final class ConfigurationResolver
{
    private readonly ApplicationDetector $applicationDetector;

    public function __construct()
    {
        $this->applicationDetector = new ApplicationDetector();
    }

    public function getConfig(): RacoonyConfig
    {
        $config = $this->getConfigFromRootPath();

        if ([] === $config->getPath()) {
            $config->setPath(getcwd());
        }

        $applicationData = $this->applicationDataResolver($config);

        if ([] === $config->getRules()) {
            $config->setPackageRules(
                match (strtoupper($applicationData->frameworkName)) {
                    'laravel' => [RuleSet::LARAVEL, RuleSet::PHP],
                    default => [RuleSet::PHP],
                },
            );
        }

        $config->setApplication($applicationData);

        return $config;
    }

    private function applicationDataResolver(RacoonyConfig $config): ApplicationData
    {
        if (null !== $config->getApplication()) {
            return $config->getApplication();
        }

        return $this->applicationDetector->detect($config->getRootPath());
    }

    private function getConfigFromRootPath(): RacoonyConfig
    {
        $configFile = getcwd() . DIRECTORY_SEPARATOR . '.racoony-config.php';

        if (file_exists($configFile) && is_readable($configFile)) {
            /** @var RacoonyConfig $config */
            $config = require $configFile;

            return $config;
        }

        /** @var RacoonyConfig $defaultConfig */
        $defaultConfig = require __DIR__ . '/../.racoony-config.php';

        return $defaultConfig;
    }
}
