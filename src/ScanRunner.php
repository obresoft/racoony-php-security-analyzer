<?php

declare(strict_types=1);

namespace Obresoft\Racoony;

use Obresoft\Racoony\CodeScanner\ASTFileScanner;
use Obresoft\Racoony\CodeScanner\Scanner;
use Obresoft\Racoony\DataFlow\ProjectDataFlowBuilder;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\Rule;
use SplFileInfo;
use Traversable;

use function is_array;

/**
 * @template T of Rule
 * @param Scanner<T> $scanner
 */
final readonly class ScanRunner
{
    /**
     * @param Traversable<array-key, SplFileInfo> $fileIterator
     * @param Scanner<T> $scanner
     * @param array<class-string<T>> $rules
     */
    public function __construct(
        private iterable $fileIterator,
        private Scanner $scanner,
        private iterable $rules,
    ) {}

    /** @return list<Insight> */
    public function run(): iterable
    {
        $insights = [];

        $filesArray = is_array($this->fileIterator)
            ? $this->fileIterator
            : iterator_to_array($this->fileIterator);

        $projectIndex = (new ProjectDataFlowBuilder())->build($filesArray);

        $scanner = $this->scanner;
        if ($scanner instanceof ASTFileScanner) {
            $scanner = $scanner->withProjectDataFlowIndex($projectIndex);
        }

        foreach ($filesArray as $file) {
            foreach ($this->rules as $rule) {
                $rule = new $rule($file->getRealPath());
                $insights = [
                    ...$insights,
                    ...$scanner->scan($file->getRealPath(), $rule),
                ];
            }
        }

        return $insights;
    }
}
