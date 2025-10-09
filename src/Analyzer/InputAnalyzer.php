<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Variable;

use function in_array;
use function is_string;
use function strtolower;

final class InputAnalyzer extends BaseAnalyzer implements AnalyzerInterface
{
    /** @var list<string> */
    private const array SUPERGLOBALS = [
        '_get',
        '_post',
        '_request',
        '_cookie',
        '_files',
        '_env',
        '_session',
    ];

    public function __construct(
        protected Scope $scope,
    ) {}

    public function isUserInputExpr(?Node $expr = null): bool
    {
        $expr ??= $this->scope->node() instanceof Expr ? $this->scope->node() : null;
        if (!$expr) {
            return false;
        }

        // $_GET, $_POST, ...
        if ($expr instanceof Variable && is_string($expr->name)) {
            return in_array(strtolower($expr->name), self::SUPERGLOBALS, true);
        }

        // $_GET['x'], $_POST['y'], ...
        if ($expr instanceof ArrayDimFetch) {
            $var = $expr->var;
            if ($var instanceof ArrayDimFetch) {
                return $this->isUserInputExpr($var->var);
            }

            if ($var instanceof Variable && is_string($var->name)) {
                return in_array(strtolower($var->name), self::SUPERGLOBALS, true);
            }
        }

        return false;
    }

    public function anyArgIsUserInput(): bool
    {
        foreach ($this->scope->callAnalyzer()->argScopes() as $argScope) {
            if ($argScope instanceof Scope && $this->isUserInputExpr(
                $argScope->node() instanceof Expr ? $argScope->node() : null,
            )) {
                return true;
            }
        }

        return false;
    }

    public function isSuperGlobalInput(): bool
    {
        if (!$this->scope->isVariable()) {
            return false;
        }

        $varName = $this->scope->nameAsString();

        return null !== $varName && in_array(strtolower($varName), self::SUPERGLOBALS, true);
    }
}
