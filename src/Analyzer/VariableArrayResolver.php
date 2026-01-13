<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Variable;

use function is_string;
use function strtolower;

final readonly class VariableArrayResolver implements AnalyzerInterface
{
    public function __construct(
        private Scope $scope,
    ) {}

    /** Returns the last Array_ literal assigned to $variableName before current line, if any. */
    public function resolveArrayFromVariableAssignment(string $variableName): ?Array_
    {
        $candidateArray = null;
        $currentLine = $this->scope->getLine();

        foreach ($this->scope->getNodes() as $astNode) {
            if (!$astNode instanceof Assign) {
                continue;
            }

            // $options = [...]
            if ($astNode->var instanceof Variable && is_string($astNode->var->name)) {
                if (strtolower($astNode->var->name) !== strtolower($variableName)) {
                    continue;
                }

                if ($astNode->getLine() > $currentLine) {
                    continue;
                }

                if ($astNode->expr instanceof Array_) {
                    $candidateArray = $astNode->expr;
                }
            }
        }

        return $candidateArray;
    }

    public function resolveIncrementalArrayWrites(string $variableName): ?array
    {
        $normalized = [];
        $sawAny = false;
        $currentLine = $this->scope->getLine();

        foreach ($this->scope->getNodes() as $astNode) {
            if (!$astNode instanceof Assign) {
                continue;
            }

            if ($astNode->getLine() > $currentLine) {
                continue;
            }

            // $options['key'] = <expr>;
            if ($astNode->var instanceof ArrayDimFetch
                && $astNode->var->var instanceof Variable
                && is_string($astNode->var->var->name)
                && strtolower($astNode->var->var->name) === strtolower($variableName)
                && $astNode->var->dim instanceof Node\Scalar\String_
            ) {
                $normalized[strtolower($astNode->var->dim->value)] = $astNode->expr;
                $sawAny = true;
            }
        }

        return $sawAny ? $normalized : null;
    }
}
