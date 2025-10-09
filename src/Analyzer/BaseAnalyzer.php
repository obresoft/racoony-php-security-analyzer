<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

abstract class BaseAnalyzer
{
    protected Scope $scope;

    final public function withScope(Scope $scope): static
    {
        $clone = clone $this;
        $clone->scope = $scope;

        return $clone;
    }
}
