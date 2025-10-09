<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer\Laravel;

use Obresoft\Racoony\Analyzer\AnalyzerInterface;
use Obresoft\Racoony\Analyzer\BaseAnalyzer;
use Obresoft\Racoony\Analyzer\Scope;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;

use function in_array;

final class LaravelRedirectAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    /** @var list<string> */
    private const array REDIRECT_METHODS = [
        'to',
        'away',
        'route',
        'action',
        'back',
        'refresh',
        'secure',
        'guest',
        'intended',
    ];

    /** @var list<string> */
    private const array DANGEROUS_METHODS = [
        'to',
        'away',
        'back',
        'guest',
        'intended',
    ];

    /** @var list<string> */
    private const array REDIRECT_FUNCTIONS = ['redirect'];

    /** @var list<string> */
    private const array REDIRECT_CLASSES = [
        'Illuminate\Http\RedirectResponse',
        'Illuminate\Routing\Redirector',
        'Redirect',
    ];

    public function __construct(protected Scope $scope) {}

    public function isRedirectMethodCall(): bool
    {
        $methodCall = $this->scope->node();
        $methodName = null;

        if ($methodCall->name instanceof Identifier || $methodCall->name instanceof Name) {
            $methodName = $methodCall->name->toString();
        } elseif ($methodCall->name instanceof Variable) {
            return false;
        }

        if (!in_array($methodName, self::REDIRECT_METHODS, true) && !in_array($methodName, self::REDIRECT_FUNCTIONS, true)) {
            return false;
        }

        if ($methodCall instanceof StaticCall) {
            return $this->isRedirectReceiver($methodCall);
        }

        if ($methodCall instanceof FuncCall) {
            return $this->isRedirectReceiver($methodCall);
        }

        if (null === $methodCall->var) {
            return false;
        }

        return $this->isRedirectReceiver($methodCall->var);
    }

    public function isDangerousMethodCall(): bool
    {
        if (!$this->isRedirectMethodCall()) {
            return false;
        }

        $methodCall = $this->scope->callAnalyzer()->calleeName();

        return in_array($methodCall, self::DANGEROUS_METHODS, true);
    }

    private function isRedirectReceiver(Node $var): bool
    {
        if ($var instanceof FuncCall && $var->name instanceof Name) {
            return in_array($var->name->toString(), self::REDIRECT_FUNCTIONS, true);
        }

        if ($var instanceof New_ && $var->class instanceof Name) {
            return in_array($var->class->toString(), self::REDIRECT_CLASSES, true);
        }

        return true;
    }
}
