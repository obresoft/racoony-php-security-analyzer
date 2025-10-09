<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

final readonly class ValueFact
{
    /**
     * @param list<ChainStep>|list<ValueFact> $meta
     */
    public function __construct(
        public FactKind $kind,
        public Scope $scope,
        public string $nameOrValue,
        public int $line,
        public array $meta = [],
    ) {}
}
