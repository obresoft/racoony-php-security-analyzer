<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests;

use Obresoft\Racoony\SourceCodeProvider;
use RuntimeException;

use function array_key_exists;

final class FileReaderFake implements SourceCodeProvider
{
    /** @var array<string, string> */
    private array $fakeFiles;

    /**
     * @param array<string, string> $fakeFiles [path => content]
     */
    public function __construct(array $fakeFiles)
    {
        $this->fakeFiles = $fakeFiles;
    }

    public function read(string $source): string
    {
        if (!array_key_exists($source, $this->fakeFiles)) {
            throw new RuntimeException("Fake file not found for path: {$source}");
        }

        return $this->fakeFiles[$source];
    }
}
