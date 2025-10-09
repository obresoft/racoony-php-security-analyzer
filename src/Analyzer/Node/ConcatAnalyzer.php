<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Node;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use PhpParser\Node\Expr\BinaryOp\Concat;

final class ConcatAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    public function __construct(
        protected Scope $scope,
    ) {}

    public function isConcat(): bool
    {
        return $this->scope->node() instanceof Concat;
    }

    /**
     * @return list<Scope>
     */
    public function concatPartScopes(): array
    {
        $currentNode = $this->scope->node();

        if (!$currentNode instanceof Concat) {
            return [$this->scope];
        }

        $partScopes = [];
        $this->collectConcatParts($this->scope, $partScopes);

        return $partScopes;
    }

    /**
     * @param list<Scope> $collector
     */
    private function collectConcatParts(Scope $currentScope, array &$collector): void
    {
        $node = $currentScope->node();

        if ($node instanceof Concat) {
            $this->collectConcatParts($currentScope->withNode($node->left), $collector);
            $this->collectConcatParts($currentScope->withNode($node->right), $collector);

            return;
        }

        $collector[] = $currentScope;
    }
}
