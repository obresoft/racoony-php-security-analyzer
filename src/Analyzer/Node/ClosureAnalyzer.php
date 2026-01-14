<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Node;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\Scope;
use PhpParser\Node;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure as ClosureNode;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\NodeFinder;

final readonly class ClosureAnalyzer implements AnalyzerInterface
{
    public function __construct(
        private Scope $scope,
    ) {}

    public function isClosure(): bool
    {
        $node = $this->scope->node();

        return $node instanceof ClosureNode || $node instanceof ArrowFunction;
    }

    /**
     * @return list<Scope>
     */
    public function closureInvocationScopes(): array
    {
        $currentNode = $this->scope->node();

        if (!$currentNode instanceof ClosureNode && !$currentNode instanceof ArrowFunction) {
            return [];
        }

        /** @var Node[] $searchRoots */
        $searchRoots = [];

        if ($currentNode instanceof ClosureNode) {
            $searchRoots = $currentNode->stmts;
        } elseif ($currentNode instanceof ArrowFunction && $currentNode->expr instanceof Node) {
            $searchRoots = [$currentNode->expr];
        }

        $nodeFinder = new NodeFinder();

        /** @var list<Node> $invocationNodes */
        $invocationNodes = $nodeFinder->find(
            $searchRoots,
            // We consider any "invocation-like" constructs as targets:
            // - FuncCall: request(), DB(), etc.
            // - MethodCall: $q->whereRaw(), request()->input(), etc.
            // - StaticCall: DB::raw(), SomeClass::make(), etc.
            // - Include_: include/require (code execution surface)
            // - New_: new SomeClass(...) (can create dynamic objects used in sinks)

            static fn (Node $node): bool => $node instanceof FuncCall
            || $node instanceof MethodCall
            || $node instanceof StaticCall
            || $node instanceof Include_
            || $node instanceof New_,
        );

        $invocationScopes = [];

        foreach ($invocationNodes as $invocationNode) {
            $invocationScopes[] = $this->scope->withNode($invocationNode);
        }

        return $invocationScopes;
    }
}
