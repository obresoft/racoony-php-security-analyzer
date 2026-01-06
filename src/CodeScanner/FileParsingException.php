<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use PhpParser\Error as PhpParserError;
use RuntimeException;

use function sprintf;

final class FileParsingException extends RuntimeException
{
    public static function fromPhpParserError(string $filePath, PhpParserError $error): self
    {
        return new self(
            sprintf('File parsing exception %s: %s', $filePath, $error->getMessage()),
            $error->getCode(),
            $error,
        );
    }
}

