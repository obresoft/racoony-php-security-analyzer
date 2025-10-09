<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Laravel;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Analyzer\ValueFact;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;

use function in_array;
use function is_string;
use function strtolower;

final class LaravelRequestCallAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    private const int MAX_VALIDATION_RECURSION_DEPTH = 8;

    /** @var list<string> */
    private const array REQUEST_CLASSES = ['Illuminate\Http\Request', 'Illuminate\Foundation\Http\FormRequest'];

    /** @var list<string> */
    private const array REQUEST_METHODS = [
        'input',
        'get',
        'post',
        'query',
        'cookie',
        'file',
        'header',
        'server',
        'json',
        'all',
        'only',
        'except',
    ];

    public function __construct(
        protected Scope $scope,
        private readonly ?ClassNameResolver $resolver = null,
    ) {}

    /**
     * Checks if the current node represents a method call on a Laravel Request object
     * or the global request() helper, targeting one of the known input methods.
     */
    public function isRequestMethodCall(): bool
    {
        if (!$this->scope->callAnalyzer()->isCallLike()) {
            return false;
        }

        $calledMethodName = $this->scope->callAnalyzer()->calleeName();

        if ($this->scope->callAnalyzer()->isFuncCall() && 'request' === $calledMethodName) {
            return true;
        }

        if (null === $calledMethodName || !in_array($calledMethodName, self::REQUEST_METHODS, true)) {
            return false;
        }

        $call = $this->scope->matchMethodCall();

        if (null === $call?->var) {
            return false;
        }

        $leftmostReceiver = $this->scope->withNode($call->var)->findLeftmostReceiver();

        // Case 1: $request->...->method()
        if ($leftmostReceiver instanceof Variable && is_string($leftmostReceiver->name)) {
            $resolvedType = $this->resolver?->resolveVariableType($leftmostReceiver->name);

            return null !== $resolvedType && in_array($resolvedType, self::REQUEST_CLASSES, true);
        }

        // Case 2: request()->...->method()
        if ($this->isRequestHelperCall($leftmostReceiver)) {
            return true;
        }

        return false;
    }

    /**
     * Checks if any of the arguments in the current scope resolves to a Request instance.
     */
    public function anyArgResolvesToRequest(): bool
    {
        $scope = $this->scope;
        $reqSet = array_flip(self::REQUEST_CLASSES);

        foreach ($scope->callAnalyzer()->argScopes() as $argScope) {
            if (!$argScope->isVariable()) {
                continue;
            }

            $name = $argScope->nameAsString();
            if (null === $name) {
                continue;
            }

            foreach ($argScope->analyzeVariable($name) as $entry) {
                $resolved = $this->resolveEntryToClass($entry);
                if (null !== $resolved && isset($reqSet[$resolved])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Detects calls that return validated (whitelisted) input from Laravel Request / FormRequest.
     *
     * Covered patterns:
     *   - $request->validate()
     *   - $request->validated()
     *   - request()->validated()
     *   - $request->safe()->only([...])
     *   - $request->safe()->except([...])
     *   - $request->safe()->all()
     *   - $request->safe()->keys()
     *   - helper variants: request()->safe()->only(...), etc.
     */
    public function isValidatedCall(int $depth = 0): bool
    {
        if ($depth > self::MAX_VALIDATION_RECURSION_DEPTH) {
            return false;
        }

        $node = $this->scope->node();
        if (!$node instanceof Expr) {
            return false;
        }

        if ($node instanceof ArrayDimFetch) {
            $baseExpr = $node->var;

            return $this->withScope($this->scope->withNode($baseExpr))
                ->isValidatedCall($depth + 1);
        }

        // Case 2: Variable whose origin may be a validated-returning MethodCall
        if ($node instanceof Variable && is_string($node->name)) {
            $facts = $this->scope->analyzeVariable($node->name);

            foreach ($facts as $fact) {
                if ($fact->scope->callAnalyzer()->isMethodCall()) {
                    return $this->withScope($this->scope->withNode($fact->scope->node()))
                        ->isValidatedCall($depth + 1);
                }
            }

            return false;
        }

        // Case 3: Direct method call patterns ($request->validate(), $request->validated(), $request->safe()->only(...))
        if ($node instanceof MethodCall && $node->name instanceof Identifier) {
            $methodName = strtolower($node->name->toString());

            if ('validate' === $methodName) {
                return $this->isRequestLikeReceiver($node->var);
            }

            if ('validated' === $methodName) {
                return $this->isRequestLikeReceiver($node->var);
            }

            $safeTerminalMethods = ['only', 'except', 'all', 'keys'];
            if (in_array($methodName, $safeTerminalMethods, true)) {
                if ($node->var instanceof MethodCall && $node->var->name instanceof Identifier) {
                    $intermediateMethodName = strtolower($node->var->name->toString());
                    if ('safe' === $intermediateMethodName) {
                        return $this->isRequestLikeReceiver($node->var->var);
                    }
                }
            }

            return $this->withScope($this->scope->withNode($node->var))
                ->isValidatedCall($depth + 1);
        }

        if ($node instanceof FuncCall && $node->name instanceof Name) {
            return false;
        }

        return false;
    }

    private function isRequestHelperCall(Node $node): bool
    {
        if ($node instanceof FuncCall && $node->name instanceof Name) {
            return 'request' === strtolower($node->name->toString());
        }

        return false;
    }

    private function isRequestLikeReceiver(Expr $receiverExpression): bool
    {
        if ($receiverExpression instanceof FuncCall && $receiverExpression->name instanceof Name) {
            return 'request' === strtolower($receiverExpression->name->toString());
        }

        if ($receiverExpression instanceof Variable && is_string($receiverExpression->name)) {
            $resolvedType = $this->resolver?->resolveVariableType($receiverExpression->name);

            if (null === $resolvedType) {
                return false;
            }

            return in_array($resolvedType, self::REQUEST_CLASSES, true);
        }

        return false;
    }

    /**
     * Resolves a ValueFact to its corresponding class name, if possible.
     */
    private function resolveEntryToClass(ValueFact $entry): ?string
    {
        $scope = $entry->scope;

        if (!$scope->callAnalyzer()->isCallLike()) {
            return null;
        }

        $className = $scope->callAnalyzer()->getCalledMethodClassName();

        if (null === $className) {
            return null;
        }

        return $this->resolver?->resolveClassName($className);
    }
}
