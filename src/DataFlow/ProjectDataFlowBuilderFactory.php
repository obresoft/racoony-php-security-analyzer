<?php

declare(strict_types=1);

namespace Obresoft\Racoony\DataFlow;

use Obresoft\Racoony\Resolver\FrameworkMetadataResolvers;
use Obresoft\Racoony\Resolver\Laravel\LaravelEloquentTableResolver;
use Obresoft\Racoony\SourceCodeProvider;

final class ProjectDataFlowBuilderFactory
{
    public static function create(SourceCodeProvider $fileReader): ProjectDataFlowBuilder
    {
        $resolvers = [
            new FrameworkMetadataResolvers(
                [
                    new LaravelEloquentTableResolver(),
                ],
            ),
        ];

        return new ProjectDataFlowBuilder(
            $fileReader,
            $resolvers,
        );
    }
}
