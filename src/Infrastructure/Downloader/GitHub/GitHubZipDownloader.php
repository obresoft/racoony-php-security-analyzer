<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Infrastructure\Downloader\GitHub;

use Obresoft\Racoony\Infrastructure\Downloader\ZipDownloader;
use RuntimeException;
use ZipArchive;

use function count;
use function sprintf;

final class GitHubZipDownloader implements ZipDownloader
{
    /** @return non-empty-string */
    public function download(string $repoUrl): string
    {
        /** @var array<string, string> $repoParts */
        $repoParts = parse_url($repoUrl);
        $pathParts = explode('/', trim($repoParts['path'], '/'));
        if (count($pathParts) < 2) {
            throw new RuntimeException('Invalid GitHub repository URL.');
        }

        $owner = $pathParts[0];
        $repo = $pathParts[1];
        $branch = 'main';

        $zipUrl = sprintf('https://github.com/%s/%s/archive/refs/heads/%s.zip', $owner, $repo, $branch);

        $tempZip = tempnam(sys_get_temp_dir(), 'zip_');
        file_put_contents($tempZip, file_get_contents($zipUrl));

        $tempDir = sys_get_temp_dir() . '/repo_' . uniqid();
        $zip = new ZipArchive();

        if (true === $zip->open($tempZip)) {
            $zip->extractTo($tempDir);
            $zip->close();
        } else {
            throw new RuntimeException('Unable to open ZIP archive.');
        }

        unlink($tempZip);

        $dirs = scandir($tempDir);
        foreach ($dirs as $dir) {
            if ('.' !== $dir && '..' !== $dir && is_dir($tempDir . '/' . $dir)) {
                return $tempDir . '/' . $dir;
            }
        }

        throw new RuntimeException('Failed to find extracted repo directory.');
    }
}
