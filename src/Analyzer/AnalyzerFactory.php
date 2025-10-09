<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use Obresoft\Racoony\Resolver\ClassNameResolver;

/**
 * @template T of AnalyzerInterface
 */
interface AnalyzerFactory
{
    /**
     * @param class-string<T> $analyzer
     * @param callable(Scope, ?ClassNameResolver): T $factory
     */
    public function register(string $analyzer, callable $factory): void;

    /**
     * @param class-string<T> $analyzer
     * @return T
     */
    public function create(string $analyzer, Scope $scope, ?ClassNameResolver $resolver = null): AnalyzerInterface;
}
