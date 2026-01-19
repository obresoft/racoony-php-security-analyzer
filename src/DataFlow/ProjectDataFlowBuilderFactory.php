<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

use Obresoft\Racoony\Resolver\Laravel\LaravelEloquentTableResolver;
use Obresoft\Racoony\Resolver\Laravel\LaravelMetadataResolvers;
use Obresoft\Racoony\SourceCodeProvider;

final class ProjectDataFlowBuilderFactory
{
    public static function create(SourceCodeProvider $fileReader, $extraFrameworkResolvers = []): ProjectDataFlowBuilder
    {
        $defaultFrameworkResolvers = [
            new LaravelMetadataResolvers(
                tables: [
                    new LaravelEloquentTableResolver(),
                ],
            ),
        ];

        return new ProjectDataFlowBuilder(
            $fileReader,
            frameworkResolvers: array_values(array_merge($defaultFrameworkResolvers, $extraFrameworkResolvers)),
        );
    }
}
