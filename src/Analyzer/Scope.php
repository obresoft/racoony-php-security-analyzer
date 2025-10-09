<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use Obresoft\Racoony\Analyzer\Node\ArrayAnalyzer;
use Obresoft\Racoony\Analyzer\Node\AttributeAnalyzer;
use Obresoft\Racoony\Analyzer\Node\CallAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ClosureAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ConcatAnalyzer;
use Obresoft\Racoony\Analyzer\Node\ParamAnalyzer;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\NullsafePropertyFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\ShellExec;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\Encapsed;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;

use function is_string;
use function strtolower;

final class Scope
{
    /**
     * @param Node[] $nodes
     */
    public function __construct(
        private Node $node,
        private readonly array $nodes,
        private readonly VariableAnalyzer $variableAnalyzer,
    ) {}

    public function node(): Node
    {
        return $this->node;
    }

    public function getLine(): int
    {
        return $this->node->getLine();
    }

    /**
     * @phpstan-assert-if-true New_ $this->node
     */
    public function isNew(): bool
    {
        return $this->node instanceof New_ && $this->node->class instanceof Name;
    }

    /**
     * @phpstan-assert-if-true Variable $this->node
     */
    public function isVariable(): bool
    {
        return $this->node instanceof Variable;
    }

    public function isTernary(): bool
    {
        return $this->node instanceof Ternary;
    }

    public function isProperty(): bool
    {
        return $this->node instanceof Node\Stmt\Property;
    }

    public function isNamed(): bool
    {
        return $this->node instanceof Name;
    }

    public function isEval(): bool
    {
        return $this->node instanceof Expr\Eval_;
    }

    public function isInclude(): bool
    {
        return $this->node instanceof Include_;
    }

    public function getIncludeName(): ?string
    {
        if (!$this->isInclude()) {
            return null;
        }

        return match ($this->node->type) {
            Include_::TYPE_INCLUDE_ONCE => 'include_once',
            Include_::TYPE_REQUIRE => 'require',
            Include_::TYPE_REQUIRE_ONCE => 'require_once',
            default => 'include',
        };
    }

    public function nameAsString(): ?string
    {
        if ($this->node instanceof FuncCall && $this->node->name instanceof Name) {
            return $this->node->name->toString();
        }

        if ($this->node instanceof FuncCall && $this->node->name instanceof Variable) {
            return $this->node->name->name;
        }

        if (($this->node instanceof StaticCall || $this->node instanceof MethodCall)
            && $this->node->name instanceof Identifier
        ) {
            return $this->node->name->toString();
        }

        if ($this->node instanceof Variable && is_string($this->node->name)) {
            return $this->node->name;
        }

        return null;
    }

    public function classAsString(): ?string
    {
        if ($this->node instanceof StaticCall && $this->node->class instanceof Name) {
            $resolved = $this->node->class->getAttribute('resolvedName');

            return $resolved ? $resolved->toString() : $this->node->class->toString();
        }

        if ($this->node instanceof New_
            && $this->node->class instanceof Name
        ) {
            $resolved = $this->node->class->getAttribute('resolvedName');

            return $resolved ? $resolved->toString() : $this->node->class->toString();
        }

        if ($this->node instanceof MethodCall
            && $this->node->var instanceof StaticCall
            && $this->node->var->class instanceof Name
        ) {
            $resolved = $this->node->var->class->getAttribute('resolvedName');

            return $resolved ? $resolved->toString() : $this->node->var->class->toString();
        }

        if ($this->node instanceof NullsafeMethodCall
            && $this->node->var instanceof StaticCall
            && $this->node->var->class instanceof Name
        ) {
            $resolved = $this->node->var->class->getAttribute('resolvedName');

            return $resolved ? $resolved->toString() : $this->node->var->class->toString();
        }

        if ($this->node instanceof Class_) {
            $namespaced = $this->node->namespacedName ?? null;

            if ($namespaced instanceof Name) {
                return $namespaced->toString();
            }

            return $this->node->name?->toString();
        }

        return null;
    }

    public function resolveReceiverClass(ClassNameResolver $resolver): ?string
    {
        $leftmostVariable = $this->findLeftmostVariable();
        if (!$leftmostVariable instanceof Variable || !is_string($leftmostVariable->name)) {
            return null;
        }

        foreach ($this->analyzeVariable($leftmostVariable->name) as $variableFact) {
            if ($variableFact->scope->callAnalyzer()->isCallLike()) {
                return $resolver->resolveClassName($variableFact->nameOrValue);
            }
        }

        return null;
    }

    public function rawInterpolatedParts(): array
    {
        if ($this->node instanceof Encapsed) {
            /** @var list<Node> $parts */
            return $this->node->parts;
        }

        if ($this->node instanceof ShellExec) {
            /** @var list<Node> $parts */
            return $this->node->parts;
        }

        if ($this->node instanceof Node\Scalar\InterpolatedString) {
            /** @var list<Node> $parts */
            return $this->node->parts;
        }

        return [];
    }

    public function stringValue(): ?string
    {
        if ($this->node instanceof String_) {
            return $this->node->value;
        }

        return null;
    }

    public function isNull(): bool
    {
        return $this->node instanceof ConstFetch
            && 'null' === strtolower($this->node->name->toString());
    }

    public function isPropertyFetch(): bool
    {
        return $this->node instanceof PropertyFetch;
    }

    /**
     * @return array<int, ValueFact>
     */
    public function analyzeVariable(string $varName, bool $recursive = true): array
    {
        return $this->variableAnalyzer->analyzeVariable($varName, $this, [], $recursive);
    }

    /**
     * @return Node[]
     */
    public function getNodes(): array
    {
        return $this->nodes;
    }

    public function matchMethodCall(): ?MethodCall
    {
        return $this->node instanceof MethodCall ? $this->node : null;
    }

    public function matchFuncCall(): ?FuncCall
    {
        return $this->node instanceof FuncCall ? $this->node : null;
    }

    public function matchStaticCall(): ?StaticCall
    {
        return $this->node instanceof StaticCall ? $this->node : null;
    }

    public function matchVariable(): ?Variable
    {
        return $this->node instanceof Variable ? $this->node : null;
    }

    public function matchNew(): ?New_
    {
        return $this->node instanceof New_ ? $this->node : null;
    }

    /**
     * @template T of Node
     * @param class-string<T> $class
     * @return T|null
     */
    public function nodeAs(string $class): ?Node
    {
        return $this->node instanceof $class ? $this->node : null;
    }

    public function isInterpolatedString(): bool
    {
        return $this->node instanceof ShellExec || $this->node instanceof Node\Scalar\InterpolatedString || $this->node instanceof Encapsed;
    }

    public function interpolatedPartScopes(): iterable
    {
        if (!$this->isInterpolatedString()) {
            return [];
        }

        foreach ($this->rawInterpolatedParts() as $partNode) {
            yield $this->withNode($partNode);
        }
    }

    public function withNode(Node $node): self
    {
        $clone = clone $this;
        $clone->node = $node;

        return $clone;
    }

    /**
     * Examples:
     *  - $a                     → $a
     *  - $a->b()->c             → $a
     *  - $a?->b?->c()           → $a
     *  - ($a->b())->c()->d      → $a
     */
    public function findLeftmostVariable(): ?Variable
    {
        $node = $this->node;
        while (
            $node instanceof MethodCall
            || $node instanceof NullsafeMethodCall
            || $node instanceof PropertyFetch
            || $node instanceof NullsafePropertyFetch
        ) {
            /** @var MethodCall|NullsafeMethodCall|NullsafePropertyFetch|PropertyFetch $node */
            $node = $node->var;
        }

        return $node instanceof Variable ? $node : null;
    }

    public function findLeftmostReceiver(): Node
    {
        $node = $this->node;
        while (
            $node instanceof MethodCall
            || $node instanceof NullsafeMethodCall
            || $node instanceof PropertyFetch
            || $node instanceof NullsafePropertyFetch
        ) {
            $node = $node->var;
        }

        return $node;
    }

    public function isClassCall(): bool
    {
        $node = $this->node;

        return $node instanceof Class_;
    }

    public function isClassLikeCall(string $className): bool
    {
        if (!$this->isClassCall()) {
            return false;
        }

        $literalClass = $this->classAsString();

        return $literalClass === $className;
    }

    public function getVariableName(): ?string
    {
        if (!$this->isVariable()) {
            return null;
        }
        $name = $this->node->name ?? null;

        return is_string($name) ? $name : null;
    }

    public function getRootVariable(): ?Variable
    {
        $node = $this->node;
        while (
            $node instanceof ArrayDimFetch
            || $node instanceof PropertyFetch
            || $node instanceof NullsafePropertyFetch
            || $node instanceof MethodCall
            || $node instanceof NullsafeMethodCall
        ) {
            $node = $node instanceof ArrayDimFetch ? $node->var : $node->var;
        }

        return $node instanceof Variable ? $node : null;
    }

    public function getAnalyzeVariable(): VariableAnalyzer
    {
        return $this->variableAnalyzer;
    }

    public function getNodeExpression(): ?Expr
    {
        return $this->node->expr ?? null;
    }

    public function arrayAnalyzer(): ArrayAnalyzer
    {
        return new ArrayAnalyzer($this);
    }

    public function callAnalyzer(): CallAnalyzer
    {
        return new CallAnalyzer($this);
    }

    public function concatAnalyzer(): ConcatAnalyzer
    {
        return new ConcatAnalyzer($this);
    }

    public function closureAnalyzer(): ClosureAnalyzer
    {
        return new ClosureAnalyzer($this);
    }

    public function paramAnalyzer(): ParamAnalyzer
    {
        return new ParamAnalyzer($this);
    }

    public function attributeAnalyzer(): AttributeAnalyzer
    {
        return new AttributeAnalyzer($this);
    }

    public function decomposeArgumentIntoPartScopes(): iterable
    {
        $scope = $this;
        if ($scope->arrayAnalyzer()->isArray()) {
            foreach ($scope->arrayAnalyzer()->getArrayValueScopesRecursively() as $valueScope) {
                yield $valueScope;
            }

            return;
        }

        if ($scope->isInterpolatedString()) {
            foreach ($scope->interpolatedPartScopes() as $interpolatedPartScope) {
                yield $interpolatedPartScope;
            }

            return;
        }

        if ($scope->concatAnalyzer()->isConcat()) {
            foreach ($scope->concatAnalyzer()->concatPartScopes() as $concatPartScope) {
                yield $concatPartScope;
            }

            return;
        }

        if ($scope->closureAnalyzer()->isClosure()) {
            foreach ($scope->closureAnalyzer()->closureInvocationScopes() as $closureScope) {
                foreach ($closureScope->callAnalyzer()->argScopes() as $innerArgScope) {
                    yield from $this->withNode($innerArgScope->node())->decomposeArgumentIntoPartScopes();
                }
            }

            return;
        }

        yield $scope;
    }
}
