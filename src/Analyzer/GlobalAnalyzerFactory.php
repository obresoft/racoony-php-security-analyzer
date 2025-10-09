<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use InvalidArgumentException;
use Obresoft\Racoony\Analyzer\Laravel\LaravelDBFacadeAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelModelAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRedirectAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\LaravelRequestCallAnalyzer;
use Obresoft\Racoony\Analyzer\Laravel\Packages\LaravelQueryBuilder\LaravelSpatieQueryBuilderAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ArrayAnalyzer;
use Obresoft\Racoony\Analyzer\Node\AttributeAnalyzer;
use Obresoft\Racoony\Analyzer\Node\CallAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ClassAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ClosureAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ConcatAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ParamAnalyzer;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;
use Obresoft\Racoony\Resolver\ClassNameResolver;

use function sprintf;

/**
 * @phpstan-type AnalyzerFactoryFn callable(Scope, ?ClassNameResolver, ?ProjectDataFlowIndex): AnalyzerInterface
 *
 * @implements AnalyzerFactory<AnalyzerInterface>
 */
final class GlobalAnalyzerFactory implements AnalyzerFactory
{
    /** @var array<string, AnalyzerFactoryFn> */
    private array $analyzers = [];

    public function __construct()
    {
        $this->registerAnalyzers();
    }

    /**
     * @param AnalyzerFactoryFn $factory
     */
    public function register(string $analyzer, callable $factory): void
    {
        if (isset($this->analyzers[$analyzer])) {
            throw new InvalidArgumentException(sprintf("Analyzer '%s' is already registered", $analyzer));
        }

        $this->analyzers[$analyzer] = $factory;
    }

    public function create(
        string $analyzer,
        Scope $scope,
        ?ClassNameResolver $resolver = null,
        ?ProjectDataFlowIndex $projectDataFlowIndex = null,
    ): AnalyzerInterface {
        if (!isset($this->analyzers[$analyzer])) {
            throw new InvalidArgumentException(sprintf("Analyzer of type '%s' is not registered", $analyzer));
        }

        $factory = $this->analyzers[$analyzer];

        return $factory($scope, $resolver, $projectDataFlowIndex);
    }

    private function registerAnalyzers(): void
    {
        $this->register(
            LaravelModelAnalyzer::class,
            static fn (
                Scope $scope,
                ?ClassNameResolver $resolver,
                ProjectDataFlowIndex $projectDataFlowIndex,
            ) => new LaravelModelAnalyzer($resolver, $scope, $projectDataFlowIndex),
        );

        $this->register(
            LaravelRedirectAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new LaravelRedirectAnalyzer($scope),
        );

        $this->register(
            LaravelRequestCallAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new LaravelRequestCallAnalyzer($scope, $resolver),
        );

        $this->register(
            InputAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new InputAnalyzer($scope),
        );

        $this->register(
            VariableArrayResolver::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new VariableArrayResolver($scope),
        );

        $this->register(
            ArrayAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new ArrayAnalyzer($scope),
        );

        $this->register(
            CallAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new CallAnalyzer($scope),
        );

        $this->register(
            ClassAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new ClassAnalyzer(),
        );

        $this->register(
            LaravelDBFacadeAnalyzer::class,
            static fn (
                Scope $scope,
                ?ClassNameResolver $resolver,
                ProjectDataFlowIndex $projectDataFlowIndex,
            ) => new LaravelDBFacadeAnalyzer($resolver, $scope),
        );

        $this->register(
            ConcatAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new ConcatAnalyzer($scope),
        );

        $this->register(
            ClosureAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new ClosureAnalyzer($scope),
        );

        $this->register(
            ParamAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new ParamAnalyzer($scope),
        );

        $this->register(
            AttributeAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new AttributeAnalyzer($scope),
        );

        $this->register(
            LaravelSpatieQueryBuilderAnalyzer::class,
            static fn (Scope $scope, ?ClassNameResolver $resolver) => new LaravelSpatieQueryBuilderAnalyzer($scope, $resolver),
        );
    }
}
