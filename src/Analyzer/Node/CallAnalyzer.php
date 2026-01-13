<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Node;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\Scope;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;

use function count;
use function strtolower;

final readonly class CallAnalyzer implements AnalyzerInterface
{
    public function __construct(
        private Scope $scope,
    ) {}

    /**
     * @phpstan-assert-if-true FuncCall $this->node()
     */
    public function isFuncCall(): bool
    {
        $node = $this->currentNode();

        return $node instanceof FuncCall
            && ($node->name instanceof Name || $node->name instanceof Expr\Variable);
    }

    /**
     * @phpstan-assert-if-true MethodCall $this->node()
     */
    public function isMethodCall(): bool
    {
        return $this->currentNode() instanceof MethodCall;
    }

    /**
     * @phpstan-assert-if-true StaticCall $this->node()
     */
    public function isStaticCall(): bool
    {
        $node = $this->currentNode();

        return $node instanceof StaticCall;
    }

    public function isCallLike(): bool
    {
        if ($this->isFuncCall()) {
            return true;
        }

        if ($this->isMethodCall()) {
            return true;
        }

        return $this->isStaticCall();
    }

    /**
     * @return list<Arg>
     */
    public function rawArgs(): array
    {
        $node = $this->currentNode();

        if ($node instanceof FuncCall) {
            return $node->args;
        }

        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
            return $node->args;
        }

        if ($node instanceof StaticCall) {
            return $node->args;
        }

        if ($node instanceof Expr\New_) {
            return $node->args;
        }

        return [];
    }

    public function hasArgs(int $min = 1): bool
    {
        return count($this->rawArgs()) >= $min;
    }

    public function argCount(): int
    {
        return count($this->rawArgs());
    }

    public function argExpr(int $index): ?Expr
    {
        $args = $this->rawArgs();

        return $args[$index]->value ?? null;
    }

    public function firstArg(): ?Expr
    {
        return $this->argExpr(0);
    }

    public function namedArgExpr(string $name): ?Expr
    {
        foreach ($this->rawArgs() as $arg) {
            if ($arg->name instanceof Identifier && strtolower($arg->name->toString()) === strtolower($name)) {
                return $arg->value;
            }
        }

        return null;
    }

    /** @return iterable<Scope> */
    public function argScopes(): iterable
    {
        if (!$this->hasArgs()) {
            return [];
        }

        foreach ($this->rawArgs() as $arg) {
            yield $this->scope->withNode($arg->value);
        }
    }

    public function firstArgScope(): ?Scope
    {
        if (!$this->hasArgs()) {
            return null;
        }

        $first = $this->firstArg();
        if (!$first instanceof Expr) {
            return null;
        }

        return $this->scope->withNode($first);
    }

    public function getSecondArgumentAsScope(): ?Scope
    {
        return $this->argumentAsScope(1);
    }

    public function argumentAsScope(int $index = 0): ?Scope
    {
        if (!$this->hasArgs()) {
            return null;
        }

        $arg = $this->argExpr($index);
        if (!$arg instanceof Expr) {
            return null;
        }

        return $this->scope->withNode($arg);
    }

    /**
     * func() => "func"
     * Class::method() => "Class::method"
     * $obj->method() => "method".
     */
    public function calleeName(): ?string
    {
        $node = $this->currentNode();

        if ($node instanceof FuncCall) {
            return $this->scope->nameAsString();
        }

        if ($node instanceof StaticCall) {
            return $this->scope->nameAsString() ?? null;
        }

        if ($node instanceof MethodCall) {
            return $this->scope->nameAsString();
        }

        return null;
    }

    public function isFunctionNamed(string $function): bool
    {
        return $this->isFuncCall()
            && strtolower($this->scope->nameAsString() ?? '') === strtolower($function);
    }

    public function isMethodNamed(string $method): bool
    {
        return $this->isMethodCall()
            && strtolower($this->scope->nameAsString() ?? '') === strtolower($method);
    }

    public function isStaticCallOf(string $class, ?string $method = null): bool
    {
        if (!$this->isStaticCall()) {
            return false;
        }

        $sameClass = strtolower($this->scope->classAsString() ?? '') === strtolower($class);
        if (!$sameClass) {
            return false;
        }

        return null === $method || strtolower($this->scope->nameAsString() ?? '') === strtolower($method);
    }

    public function getCalledMethodClassName(): ?string
    {
        if (!$this->isCallLike()) {
            return null;
        }

        if ($this->isStaticCall() && $this->scope->node()?->class instanceof Name) {
            return $this->scope->node()?->class->name;
        }

        if (!isset($this->scope->node()?->var)) {
            return null;
        }

        $calleeScope = $this->scope->withNode($this->scope->node()->var);

        if ($calleeScope->isVariable()) {
            $typeList = $this->scope->getAnalyzeVariable()->getParamTypes($calleeScope->getVariableName());

            if ([] === $typeList) {
                return null;
            }

            return $typeList[0];
        }

        return $this->scope->node()->var->class->name ?? null;
    }

    /**
     * @return list<Expr\ArrowFunction|Expr\Closure>
     */
    public function getClosureNodes(): array
    {
        $currentNode = $this->currentNode();
        $collectedClosures = [];

        for (
            $node = $currentNode;
            $node instanceof MethodCall || $node instanceof NullsafeMethodCall || $node instanceof StaticCall || $node instanceof FuncCall;
            $node = $node instanceof MethodCall || $node instanceof NullsafeMethodCall ? $node->var : null
        ) {
            /** @var Arg $arg */
            foreach ($node->args as $arg) {
                $value = $arg->value;
                if ($value instanceof Expr\Closure || $value instanceof Expr\ArrowFunction) {
                    $collectedClosures[] = $value;
                }
            }
        }

        return array_reverse($collectedClosures);
    }

    private function currentNode(): Node
    {
        return $this->scope->node();
    }
}
