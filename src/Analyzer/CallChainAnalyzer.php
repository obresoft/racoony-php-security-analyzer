<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;

final readonly class CallChainAnalyzer implements AnalyzerInterface
{
    public function __construct(private Scope $scope) {}

    /**
     * Finds a method call inside a chained call expression and returns Scope bound to that MethodCall node.
     *
     * Example:
     * DB::table('users')->select(['id'])->where('active', 1)
     * Will return the Scope for the "select(...)" MethodCall when $methodName = "select".
     */
    public function findLastMethodCallScope(string $methodName): ?Scope
    {
        return $this->findLastMethodCallScopeFrom($methodName, $this->scope);
    }

    private function findLastMethodCallScopeFrom(string $methodName, Scope $scope): ?Scope
    {
        $currentNode = $scope->node();

        while ($currentNode instanceof Node) {
            if ($this->isMethodCallNamed($currentNode, $methodName)) {
                return $scope->withNode($currentNode);
            }

            if ($this->scope->withNode($currentNode)->isVariable()) {
                $analyzeVariable = $this->scope->withNode($currentNode)
                    ->analyzeVariable($this->scope->withNode($currentNode)->getVariableName());

                foreach ($analyzeVariable as $variable) {
                    if ($variable->scope->callAnalyzer()->isCallLike()
                        && $this->isMethodCallNamed($variable->scope->node(), $methodName)) {
                        return $scope->withNode($variable->scope->node());
                    }
                }

                return null;
            }

            $currentNode = $this->getPreviousChainNode($currentNode);

            if (!$currentNode instanceof Node) {
                return null;
            }
        }

        return null;
    }

    private function isMethodCallNamed(Node $node, string $methodName): bool
    {
        $calledName = $this->getCalledMethodName($node);

        return null !== $calledName && $calledName === $methodName;
    }

    private function getCalledMethodName(Node $node): ?string
    {
        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $name = $node->name->toString();

                return '' !== $name ? $name : null;
            }

            return null;
        }

        if ($node instanceof StaticCall) {
            return $node->name instanceof Node\Identifier
                ? $node->name->toString()
                : null;
        }

        return null;
    }

    private function getPreviousChainNode(Node $node): ?Node
    {
        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
            return $node->var instanceof Node ? $node->var : null;
        }

        return null;
    }
}
