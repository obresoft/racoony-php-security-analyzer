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
    private const array DIRECT_USER_INPUT = [
        '_get',
        '_post',
        '_request',
        '_cookie',
        '_files',
    ];

    private const array NON_USER_INPUT = [
        '_env',
        '_session',
        '_server',
    ];

    public function __construct(
        protected Scope $scope,
    ) {}

    public function isUserControlledInput(?Node $expr = null): bool
    {
        $allSuperGlobals = array_merge(self::DIRECT_USER_INPUT, self::NON_USER_INPUT);
        $expr ??= $this->scope->node() instanceof Expr ? $this->scope->node() : null;
        if (!$expr instanceof Node) {
            return false;
        }

        // $_GET, $_POST, ...
        if ($expr instanceof Variable && is_string($expr->name)) {
            return in_array(strtolower($expr->name), $allSuperGlobals, true);
        }

        // $_GET['x'], $_POST['y'], ...
        if ($expr instanceof ArrayDimFetch) {
            $var = $expr->var;
            if ($var instanceof ArrayDimFetch) {
                return $this->isUserControlledInput($var->var);
            }

            if ($var instanceof Variable && is_string($var->name)) {
                return in_array(strtolower($var->name), $allSuperGlobals, true);
            }
        }

        return false;
    }

    public function anyArgIsUserInput(): bool
    {
        foreach ($this->scope->callAnalyzer()->argScopes() as $argScope) {
            if ($argScope instanceof Scope && $this->isUserControlledInput(
                $argScope->node() instanceof Expr ? $argScope->node() : null,
            )) {
                return true;
            }
        }

        return false;
    }
}
