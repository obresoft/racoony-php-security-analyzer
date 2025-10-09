<?php

declare(strict_types=1);

namespace Obresoft\Racoony;

use RuntimeException;

use function error_get_last;
use function file_get_contents;
use function sprintf;

final class FileReader implements SourceCodeProvider
{
    public function read(string $source): string
    {
        $content = @file_get_contents($source);

        if (false === $content) {
            $error = error_get_last();

            throw new RuntimeException(sprintf(
                'Failed to read content from "%s".%s',
                $source,
                null !== $error ? ' ' . $error['message'] : '',
            ));
        }

        return $content;
    }
}
