<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\ArrayItem;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat as ConcatAssign;
use PhpParser\Node\Expr\BinaryOp\Coalesce;
use PhpParser\Node\Expr\BinaryOp\Concat as BinConcat;
use PhpParser\Node\Expr\BooleanNot;
use PhpParser\Node\Expr\Cast;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Isset_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\NullsafePropertyFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\DNumber;
use PhpParser\Node\Scalar\Encapsed;
use PhpParser\Node\Scalar\LNumber;
use PhpParser\Node\Scalar\String_;

use function in_array;
use function is_string;
use function sprintf;

final class VariableAnalyzer
{
    private const int MAX_DEPTH = 32;

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

    /** @var array<string, list<ValueFact>> */
    private array $cache = [];

    public function __construct(
        private readonly FileIndex $index,
    ) {}

    /**
     * @return list<ValueFact>
     */
    public function analyzeVariable(
        string $variableName,
        Scope $scope,
        array $visited = [],
        bool $recursive = true,
        int $depth = self::MAX_DEPTH,
    ): array {
        if (in_array(strtolower($variableName), self::SUPERGLOBALS, true)) {
            return [new ValueFact(
                FactKind::Scalar,
                $scope,
                $variableName,
                $scope->getLine(),
            )];
        }

        $key = $variableName . '|' . ($recursive ? 'r' : 'n');
        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        if ($depth <= 0) {
            return [];
        }

        if (in_array($variableName, $visited, true)) {
            return $this->cache[$key] = [];
        }

        $visited[] = $variableName;

        $facts = [];
        $assignments = array_reverse($this->index->getAssignments($variableName));

        foreach ($assignments as $assignment) {
            foreach ($this->analyzeAssignment($assignment, $scope, $visited, $recursive, $depth - 1) as $fact) {
                $facts[] = $fact;
            }
        }

        return $this->cache[$key] = $this->uniqueFacts($facts);
    }

    public function getParamTypes($variableName): array
    {
        return $this->index->getParamTypes($variableName);
    }

    /**
     * @return list<ValueFact>
     */
    private function analyzeAssignment(Assign|Node $assignment, Scope $scope, array $visited, bool $recursive, int $depth): array
    {
        $expression = $assignment instanceof Assign ? $assignment->expr : $assignment;
        $out = [];

        if ($expression instanceof Cast\String_) {
            return $this->analyzeAssignment($expression->expr, $scope, $visited, $recursive, $depth - 1);
        }

        // $a = func(...);
        if ($expression instanceof FuncCall) {
            $out[] = $this->factFuncCall($expression, $scope);
            foreach ($this->resolveArgsFacts($expression->args, $scope, $visited, $recursive, $depth) as $fact) {
                $out[] = $fact;
            }

            return $out;
        }

        // $a = new Class(...);
        if ($expression instanceof New_) {
            $out[] = $this->factNew($expression, $scope);
            foreach ($this->resolveArgsFacts($expression->args, $scope, $visited, $recursive, $depth) as $fact) {
                $out[] = $fact;
            }

            return $out;
        }

        // $a = $b;
        if ($expression instanceof Variable && is_string($expression->name)) {
            if ($recursive) {
                return $this->analyzeVariable($expression->name, $scope->withNode($expression), $visited, true, $depth - 1);
            }

            return [new ValueFact(
                FactKind::Scalar,
                $scope->withNode($expression),
                (string)$expression->name,
                $assignment->getLine(),
                $expression,
            )];
        }

        // $a = $_GET['id'] / $a = $arr['k']
        if ($expression instanceof ArrayDimFetch) {
            return [$this->factArrayAccess($expression, $assignment->getLine(), $scope, $visited, $recursive, $depth)];
        }

        // $a = $x . $y
        if ($expression instanceof BinConcat) {
            return [$this->factConcat($expression, $assignment->getLine(), $scope, $visited, $depth)];
        }

        // $a .= $x
        if ($expression instanceof ConcatAssign) {
            return [$this->factConcatAssign($expression, $scope)];
        }

        if ($expression instanceof Ternary) {
            return [$this->factTernary($expression, $scope, $visited, $depth)];
        }

        // $a = $b ?? $_GET['x'] ?? 'def'
        if ($expression instanceof Coalesce) {
            return [$this->factCoalesce($expression, $scope, $visited, $depth)];
        }

        // Closure / ArrowFunction
        if ($expression instanceof Closure) {
            return [$this->factClosure($expression, $scope)];
        }

        if ($expression instanceof ArrowFunction) {
            return [$this->factArrow($expression, $scope)];
        }

        // "Hello $x"
        if ($expression instanceof Encapsed) {
            return [$this->factEncapsed($expression, $assignment->getLine(), $scope, $visited, $depth)];
        }

        if ($expression instanceof String_ || $expression instanceof LNumber || $expression instanceof DNumber) {
            return [new ValueFact(
                FactKind::Scalar,
                $scope->withNode($expression),
                (string)$expression->value,
                $assignment->getLine(),
            )];
        }

        if ($expression instanceof ConstFetch) {
            return [new ValueFact(
                FactKind::ConstFetch,
                $scope->withNode($expression),
                $expression->name->toString(),
                $assignment->getLine(),
            )];
        }

        if ($expression instanceof ClassConstFetch) {
            $className = $expression->class instanceof Name ? $expression->class->toString() : 'unknown';
            $constName = $expression->name instanceof Identifier ? $expression->name->toString() : 'UNKNOWN';

            return [new ValueFact(
                FactKind::ConstFetch,
                $scope->withNode($expression),
                $className . '::' . $constName,
                $assignment->getLine(),
            )];
        }

        // $a = $obj->m()?->n; Foo::bar()
        if (
            $expression instanceof MethodCall
            || $expression instanceof NullsafeMethodCall
            || $expression instanceof PropertyFetch
            || $expression instanceof NullsafePropertyFetch
            || $expression instanceof StaticCall
        ) {
            return [$this->factChained($expression, $scope)];
        }

        // BooleanNot / Cast
        if ($expression instanceof BooleanNot || $expression instanceof Cast) {
            return [new ValueFact(
                FactKind::Expression,
                $scope->withNode($expression),
                $expression::class,
                $assignment->getLine(),
            )];
        }

        // Handle array literal: $a = [ ... ] or array( ... )
        if ($expression instanceof Array_) {
            return $this->factArrayLiteral($expression, $assignment->getLine(), $scope, $visited, $recursive, $depth);
        }

        // Fallback
        return [$this->factUnknown($expression, $assignment->getLine(), $scope)];
    }

    /**
     * @return list<ValueFact>
     */
    private function factArrayLiteral(
        Array_ $arrayExpr,
        int $line,
        Scope $scope,
        array $visited,
        bool $recursive,
        int $depth,
    ): array {
        $facts = [];

        foreach ($arrayExpr->items ?? [] as $item) {
            if ($item instanceof ArrayItem && $item->value instanceof String_) {
                $facts[] = new ValueFact(
                    FactKind::Scalar,
                    $scope->withNode($item->value),
                    $item->value->value,
                    $line,
                );
            }

            if ($item instanceof ArrayItem && $item->value instanceof Variable) {
                $rawName = $item->value->name;
                $variableName = is_string($rawName)
                    ? $rawName
                    : $this->tryResolveVariableNameFromExpr($scope->withNode($rawName));

                if (null === $variableName) {
                    continue;
                }

                if ($depth <= 0 || !$recursive) {
                    $facts[] = new ValueFact(
                        FactKind::VARIABLE,
                        $scope->withNode($item->value),
                        $variableName,
                        $line,
                    );

                    continue;
                }

                foreach ($this->analyzeVariable($variableName, $scope->withNode($item->value), $visited, true, $depth - 1) as $singleVariableInfo) {
                    $variableScope = $singleVariableInfo->scope ?? $scope;
                    $currentNode = $variableScope->node();

                    $nodeForFact = (property_exists($currentNode, 'expr') && $currentNode->expr instanceof Node)
                        ? $currentNode->expr
                        : ($currentNode instanceof Node ? $currentNode : $item->value);

                    $facts[] = new ValueFact(
                        FactKind::VARIABLE,
                        $scope->withNode($nodeForFact),
                        $variableName,
                        method_exists($item->value, 'getStartLine') ? $item->value->getStartLine() : $line,
                    );
                }
            }
        }

        return $facts;
    }

    private function tryResolveVariableNameFromExpr(Scope $exprScope): ?string
    {
        $node = $exprScope->node();

        if ($node instanceof Variable && is_string($node->name)) {
            return $node->name;
        }

        if ($node instanceof String_) {
            return $node->value;
        }

        return null;
    }

    /**
     * @return list<ValueFact>
     */
    private function resolveArgsFacts(array $args, Scope $scope, array $visited, bool $recursive, int $depth): array
    {
        $facts = [];
        /** @var Arg $arg */
        foreach ($args as $arg) {
            $value = $arg->value;
            if ($value instanceof Expr) {
                foreach ($this->resolveExpression($value, $scope, $visited, $recursive, $depth) as $fact) {
                    $facts[] = $fact;
                }
            }
        }

        return $facts;
    }

    /**
     * @return list<ValueFact>
     */
    private function resolveExpression(Expr $expr, Scope $scope, array $visited, bool $recursive, int $depth): array
    {
        if ($expr instanceof Variable && is_string($expr->name)) {
            return $this->analyzeVariable($expr->name, $scope, $visited, $recursive, $depth - 1);
        }

        if ($expr instanceof ArrayDimFetch) {
            return [$this->factArrayAccess($expr, $expr->getLine(), $scope, $visited, $recursive, $depth)];
        }

        if ($expr instanceof FuncCall) {
            return [$this->factFuncCall($expr, $scope)];
        }

        if ($expr instanceof BinConcat) {
            return [$this->factConcat($expr, $expr->getLine(), $scope, $visited, $depth)];
        }

        if ($expr instanceof Closure) {
            return [$this->factClosure($expr, $scope)];
        }

        if ($expr instanceof ArrowFunction) {
            return [$this->factArrow($expr, $scope)];
        }

        if ($expr instanceof Coalesce) {
            return [$this->factCoalesce($expr, $scope, $visited, $depth)];
        }

        if ($expr instanceof Encapsed) {
            return [$this->factEncapsed($expr, $expr->getLine(), $scope, $visited, $depth)];
        }

        if ($expr instanceof ConstFetch) {
            return [new ValueFact(
                FactKind::ConstFetch,
                $scope->withNode($expr),
                $expr->name->toString(),
                $expr->getLine(),
            )];
        }

        if ($expr instanceof ClassConstFetch) {
            $className = $expr->class instanceof Name ? $expr->class->toString() : 'unknown';
            $constName = $expr->name instanceof Identifier ? $expr->name->toString() : 'UNKNOWN';

            return [new ValueFact(
                FactKind::ConstFetch,
                $scope->withNode($expr),
                $className . '::' . $constName,
                $expr->getLine(),
            )];
        }

        if ($expr instanceof String_ || $expr instanceof LNumber || $expr instanceof DNumber) {
            return [new ValueFact(
                FactKind::Scalar,
                $scope->withNode($expr),
                (string)$expr->value,
                $expr->getLine(),
            )];
        }

        if (
            $expr instanceof MethodCall
            || $expr instanceof NullsafeMethodCall
            || $expr instanceof PropertyFetch
            || $expr instanceof NullsafePropertyFetch
            || $expr instanceof StaticCall
        ) {
            return [$this->factChained($expr, $scope)];
        }

        return [$this->factUnknown($expr, $expr->getLine(), $scope)];
    }

    private function factFuncCall(FuncCall $call, Scope $scope): ValueFact
    {
        $name = $call->name instanceof Name ? $call->name->toString() : 'unknown_func';

        return new ValueFact(
            FactKind::FUNC_CALL,
            $scope->withNode($call),
            $name,
            $call->getLine(),
        );
    }

    private function factNew(New_ $new, Scope $scope): ValueFact
    {
        $name = $new->class instanceof Name ? $new->class->toString() : 'unknown_class';

        return new ValueFact(
            FactKind::NEW,
            $scope->withNode($new),
            'new ' . $name,
            $new->getLine(),
        );
    }

    private function factArrayAccess(ArrayDimFetch $dim, int $line, Scope $scope, array $visited, bool $recursive, int $depth): ValueFact
    {
        $root = $this->getRootVar($dim);
        $keyReadable = $this->readableDimKey($dim->dim);
        $resolved = [];

        if (null !== $root && $recursive) {
            $resolved = $this->analyzeVariable($root, $scope, $visited, true, $depth - 1);
        }

        return new ValueFact(
            FactKind::ARRAY_ACCESS,
            $scope->withNode($dim),
            ($root ?? 'unknown') . sprintf('[%s]', $keyReadable),
            $line,
            meta: $resolved,
        );
    }

    private function factConcat(BinConcat $concat, int $line, Scope $scope, array $visited, int $depth): ValueFact
    {
        $parts = $this->resolveExpression($concat->left, $scope, $visited, true, $depth - 1);
        foreach ($this->resolveExpression($concat->right, $scope, $visited, true, $depth - 1) as $f) {
            $parts[] = $f;
        }

        return new ValueFact(
            FactKind::CONCAT,
            $scope->withNode($concat),
            'concat',
            $line,
            $this->uniqueFacts($parts),
        );
    }

    private function factConcatAssign(ConcatAssign $op, Scope $scope): ValueFact
    {
        $target = ($op->var instanceof Variable && is_string($op->var->name)) ? $op->var->name : 'concat_assign';

        return new ValueFact(
            FactKind::ConcatAssign,
            $scope->withNode($op),
            $target,
            $op->getLine(),
        );
    }

    private function factTernary(Ternary $ternary, Scope $scope, array $visited, int $depth): ValueFact
    {
        $meta = [];

        if ($ternary->cond instanceof Expr) {
            foreach ($this->resolveExpression($ternary->cond, $scope, $visited, true, $depth - 1) as $f) {
                $meta[] = $f;
            }
        }

        if ($ternary->cond instanceof Isset_) {
            foreach ($ternary->cond->vars as $v) {
                if ($v instanceof ArrayDimFetch) {
                    $meta[] = new ValueFact(
                        FactKind::Expression,
                        $scope->withNode($v),
                        'isset',
                        $v->getLine(),
                    );
                }
            }
        }

        if ($ternary->if instanceof Expr) {
            foreach ($this->resolveExpression($ternary->if, $scope, $visited, true, $depth - 1) as $f) {
                $meta[] = $f;
            }
        }

        if ($ternary->else instanceof Expr) {
            foreach ($this->resolveExpression($ternary->else, $scope, $visited, true, $depth - 1) as $f) {
                $meta[] = $f;
            }
        }

        return new ValueFact(
            FactKind::Ternary,
            $scope->withNode($ternary),
            'ternary',
            $ternary->getLine(),
            $this->uniqueFacts($meta),
        );
    }

    private function factCoalesce(Coalesce $coalesce, Scope $scope, array $visited, int $depth): ValueFact
    {
        $meta = [];
        $stack = [$coalesce];

        while ($stack) {
            /** @var Coalesce $node */
            $node = array_pop($stack);

            foreach ($this->resolveExpression($node->left, $scope, $visited, true, $depth - 1) as $f) {
                $meta[] = $f;
            }

            if ($node->right instanceof Coalesce) {
                $stack[] = $node->right;
            } else {
                foreach ($this->resolveExpression($node->right, $scope, $visited, true, $depth - 1) as $f) {
                    $meta[] = $f;
                }
            }
        }

        return new ValueFact(
            FactKind::Coalesce,
            $scope->withNode($coalesce),
            'coalesce',
            $coalesce->getLine(),
            $this->uniqueFacts($meta),
        );
    }

    private function factClosure(Closure $closure, Scope $scope): ValueFact
    {
        return new ValueFact(
            FactKind::Closure,
            $scope->withNode($closure),
            'closure',
            $closure->getLine(),
        );
    }

    private function factArrow(ArrowFunction $arrowFunction, Scope $scope): ValueFact
    {
        return new ValueFact(
            FactKind::ARROW_FUNCTION,
            $scope->withNode($arrowFunction),
            'arrow_function',
            $arrowFunction->getLine(),
        );
    }

    private function factChained(MethodCall|NullsafeMethodCall|NullsafePropertyFetch|PropertyFetch|StaticCall $expr, Scope $scope): ValueFact
    {
        $steps = [];
        $current = $expr;

        while (
            $current instanceof MethodCall
            || $current instanceof NullsafeMethodCall
            || $current instanceof PropertyFetch
            || $current instanceof NullsafePropertyFetch
            || $current instanceof StaticCall
        ) {
            $name = $this->nodeName($current);
            $caller = '';

            if ($current instanceof StaticCall) {
                $caller = $current->class instanceof Name ? $current->class->toString() : '';
                $steps[] = new ChainStep($current::class, $caller, $name, $current->getLine());
                $current = null;

                break;
            }

            $var = $current->var;
            if ($var instanceof Variable && is_string($var->name)) {
                $caller = FactKind::VARIABLE->value;
            } elseif ($var instanceof New_) {
                $caller = FactKind::METHOD->value;
            }

            $steps[] = new ChainStep($current::class, $caller, $name, $current->getLine());
            $current = $var;
        }

        $caller = $steps[0]->caller ?? '';

        return new ValueFact(
            FactKind::ChainedCall,
            $scope->withNode($expr),
            $caller,
            $expr->getLine(),
            $steps,
        );
    }

    private function factEncapsed(Encapsed $encapsed, int $line, Scope $scope, array $visited, int $depth): ValueFact
    {
        $parts = [];
        foreach ($encapsed->parts as $part) {
            if ($part instanceof Expr) {
                foreach ($this->resolveExpression($part, $scope, $visited, true, $depth - 1) as $f) {
                    $parts[] = $f;
                }
            } elseif (is_string($part)) {
                $parts[] = new ValueFact(
                    FactKind::Scalar,
                    $scope,
                    $part,
                    $line,
                );
            }
        }

        return new ValueFact(
            FactKind::CONCAT,
            $scope->withNode($encapsed),
            'encapsed',
            $line,
            $this->uniqueFacts($parts),
        );
    }

    private function factUnknown(Expr $expr, int $line, Scope $scope): ValueFact
    {
        return new ValueFact(
            FactKind::Unknown,
            $scope->withNode($expr),
            'unknown',
            $line,
        );
    }

    private function getRootVar(ArrayDimFetch $fetch): ?string
    {
        $current = $fetch;
        while ($current instanceof ArrayDimFetch) {
            $current = $current->var;
        }

        return $current instanceof Variable && is_string($current->name) ? $current->name : null;
    }

    private function readableDimKey(?Expr $dim): string
    {
        if ($dim instanceof String_) {
            return "'" . $dim->value . "'";
        }

        if ($dim instanceof LNumber) {
            return (string)$dim->value;
        }

        if ($dim instanceof ConstFetch) {
            return $dim->name->toString();
        }

        if ($dim instanceof ClassConstFetch) {
            $cls = $dim->class instanceof Name ? $dim->class->toString() : 'unknown';
            $cn = $dim->name instanceof Identifier ? $dim->name->toString() : 'UNKNOWN';

            return $cls . '::' . $cn;
        }

        return 'unknown_key';
    }

    private function nodeName(MethodCall|NullsafeMethodCall|NullsafePropertyFetch|PropertyFetch|StaticCall $node): string
    {
        $n = $node instanceof StaticCall ? $node->name : $node->name;

        return $n instanceof Identifier ? $n->toString() : 'unknown';
    }

    /**
     * @param list<ValueFact> $facts
     * @return list<ValueFact>
     */
    private function uniqueFacts(array $facts): array
    {
        $seen = [];
        $out = [];

        foreach ($facts as $fact) {
            $hash = $fact->kind->value . '|' . $fact->nameOrValue . '|' . $fact->line;
            if (!isset($seen[$hash])) {
                $seen[$hash] = true;
                $out[] = $fact;
            }
        }

        return $out;
    }
}
