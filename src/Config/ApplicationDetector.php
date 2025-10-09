<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Config;

use function is_array;

final class ApplicationDetector
{
    public function detect(string $projectRootPath): ApplicationData
    {
        $frameworkName = 'Unknown';
        $frameworkVersion = 'Unknown';

        $composerLockPath = $projectRootPath . '/composer.lock';
        $composerJsonPath = $projectRootPath . '/composer.json';
        $packageVersionsFromLock = [];
        $requireConstraintsFromJson = [];

        if (is_file($composerLockPath)) {
            $composerLockContent = json_decode((string)file_get_contents($composerLockPath), true);
            if (is_array($composerLockContent['packages'] ?? null)) {
                foreach ($composerLockContent['packages'] as $packageEntry) {
                    if (!empty($packageEntry['name'])) {
                        $packageVersionsFromLock[$packageEntry['name']] = $packageEntry['version'] ?? 'Unknown';
                    }
                }
            }
        }

        if (is_file($composerJsonPath)) {
            $composerJsonContent = json_decode((string)file_get_contents($composerJsonPath), true);
            if (is_array($composerJsonContent['require'] ?? null)) {
                /** @var array<string,string> $requirements */
                $requirements = $composerJsonContent['require'];
                $requireConstraintsFromJson = $requirements;
            }
        }

        // Laravel
        $laravelVersion =
            $packageVersionsFromLock['laravel/framework']
            ?? $requireConstraintsFromJson['laravel/framework']
            ?? null;

        if (null !== $laravelVersion) {
            return new ApplicationData('Laravel', (string)$laravelVersion);
        }

        // Symfony
        $symfonyCandidates = [
            'symfony/framework-bundle',
            'symfony/http-kernel',
            'symfony/symfony',
        ];
        foreach ($symfonyCandidates as $pkg) {
            $symfonyVersion =
                $packageVersionsFromLock[$pkg]
                ?? $requireConstraintsFromJson[$pkg]
                ?? null;

            if (null !== $symfonyVersion) {
                return new ApplicationData('Symfony', (string)$symfonyVersion);
            }
        }

        // WordPress
        $wordpressCandidates = [
            'johnpbloch/wordpress',
            'roots/wordpress',
        ];
        foreach ($wordpressCandidates as $pkg) {
            $wpVersion =
                $packageVersionsFromLock[$pkg]
                ?? $requireConstraintsFromJson[$pkg]
                ?? null;

            if (null !== $wpVersion) {
                return new ApplicationData('WordPress', (string)$wpVersion);
            }
        }

        if (is_dir($projectRootPath . '/wp-includes')) {
            return new ApplicationData('WordPress', 'Unknown');
        }

        return new ApplicationData($frameworkName, $frameworkVersion);
    }
}
