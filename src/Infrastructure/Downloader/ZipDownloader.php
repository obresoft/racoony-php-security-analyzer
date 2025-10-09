<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Infrastructure\Downloader;

interface ZipDownloader
{
    /** @return non-empty-string */
    public function download(string $repoUrl): string;
}
