<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;
use Obresoft\Racoony\Resolver\ClassNameResolver;

final readonly class AnalyzerResolver
{
    public function __construct(
        private Scope $scope,
        private GlobalAnalyzerFactory $factory,
        public ProjectDataFlowIndex $projectDataFlowIndex,
    ) {}

    /**
     * @template T of AnalyzerInterface
     * @param class-string<T> $analyzerClass
     * @return T
     */
    public function get(string $analyzerClass, ?Scope $scope = null): AnalyzerInterface
    {
        return $this->factory->create(
            $analyzerClass,
            $scope ?? $this->scope,
            new ClassNameResolver($this->scope->getNodes()),
            $this->projectDataFlowIndex,
        );
    }
}
