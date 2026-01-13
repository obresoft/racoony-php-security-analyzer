<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Resolver;

use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Param;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\GroupUse;
use PhpParser\Node\Stmt\Namespace_;
use PhpParser\Node\Stmt\Use_;
use PhpParser\NodeFinder;

use function array_slice;
use function count;
use function is_string;

final readonly class ClassNameResolver
{
    public function __construct(private array $allNodes) {}

    public function resolveClassName(Name|string $name): string
    {
        if ($name instanceof Name) {
            $resolvedName = $name->getAttribute('resolvedName');

            if ($resolvedName) {
                return $resolvedName->toString();
            }
        }

        $nameString = $name instanceof Name ? $name->toString() : $name;

        if (str_starts_with($nameString, '\\')) {
            return ltrim($nameString, '\\');
        }

        $useStatements = $this->collectUseStatements($this->allNodes);
        $useMapCaseInsensitive = [];
        foreach ($useStatements as $alias => $fullyQualifiedName) {
            $useMapCaseInsensitive[strtolower($alias)] = $fullyQualifiedName;
        }

        if (!str_contains($nameString, '\\')) {
            $aliasLower = strtolower($nameString);

            return $useMapCaseInsensitive[$aliasLower] ?? $nameString;
        }

        $parts = explode('\\', $nameString);
        $firstSegmentLower = strtolower($parts[0]);

        if (isset($useMapCaseInsensitive[$firstSegmentLower])) {
            $resolved = $useMapCaseInsensitive[$firstSegmentLower];

            if (count($parts) > 1) {
                $tail = implode('\\', array_slice($parts, 1));
                $resolved .= '\\' . $tail;
            }

            return $resolved;
        }

        return $nameString;
    }

    /**
     * Resolves variable type to full class name.
     */
    public function resolveVariableType(string $variableName): ?string
    {
        $allNodes = $this->allNodes;
        $useStatements = $this->collectUseStatements($allNodes);

        return $this->findVariableTypeFromAssignment($variableName, $allNodes, $useStatements)
            ?? $this->findVariableTypeFromMethodParams($variableName, $allNodes, $useStatements)
            ?? $this->findVariableTypeFromDocBlocks($variableName, $allNodes, $useStatements);
    }

    /**
     * Get all variable types in the given nodes.
     *
     * @return array<string, string> Array where key is variable name and value is full class name
     */
    public function getAllVariableTypes(): array
    {
        $allNodes = $this->allNodes;
        $nodeFinder = new NodeFinder();
        $variables = [];

        $variableNodes = $nodeFinder->find($allNodes, static fn (Node $node) => $node instanceof Variable && is_string($node->name));

        foreach ($variableNodes as $variable) {
            /** @var Variable $variable */
            $varName = $variable->name;

            if (!isset($variables[$varName])) {
                $type = $this->resolveVariableType($varName);
                if ($type) {
                    $variables[$varName] = $type;
                }
            }
        }

        return $variables;
    }

    /**
     * @param Node[] $nodes
     * @return array<string, string>
     */
    private function collectUseStatements(array $nodes): array
    {
        foreach ($nodes as $node) {
            if ($node instanceof Namespace_) {
                return $this->collectUseStatementsFromNamespaceStmts($node->stmts ?? []);
            }
        }

        return $this->collectUseStatementsFromNamespaceStmts($nodes);
    }

    /**
     * @param Node[] $stmts
     * @return array<string,string>
     */
    private function collectUseStatementsFromNamespaceStmts(array $stmts): array
    {
        $useStatements = [];

        foreach ($stmts as $stmt) {
            if ($stmt instanceof Use_) {
                foreach ($stmt->uses as $use) {
                    $useStatements[$use->getAlias()->toString()] = $use->name->toString();
                }

                continue;
            }

            if ($stmt instanceof GroupUse) {
                $prefix = $stmt->prefix->toString();
                foreach ($stmt->uses as $use) {
                    $useStatements[$use->getAlias()->toString()] = $prefix . '\\' . $use->name->toString();
                }
            }
        }

        return $useStatements;
    }

    /**
     * Find variable type from new assignments like: $request = new Request().
     */
    private function findVariableTypeFromAssignment(string $variableName, array $allNodes, array $useStatements): ?string
    {
        $nodeFinder = new NodeFinder();

        $assignments = $nodeFinder->find($allNodes, static fn (Node $node) => $node instanceof Assign
                && $node->var instanceof Variable
                && $node->var->name === $variableName
                && $node->expr instanceof New_);

        foreach ($assignments as $assignment) {
            /** @var Assign $assignment */
            $newExpr = $assignment->expr;

            if ($newExpr->class instanceof Name) {
                return $this->resolveClassNameFromString($newExpr->class->toString(), $useStatements);
            }
        }

        return null;
    }

    private function findVariableTypeFromMethodParams(string $variableName, array $allNodes, array $useStatements): ?string
    {
        $nodeFinder = new NodeFinder();

        $methods = $nodeFinder->findInstanceOf($allNodes, ClassMethod::class);

        foreach ($methods as $method) {
            /** @var ClassMethod $method */
            foreach ($method->params as $param) {
                /** @var Param $param */
                if ($param->var instanceof Variable
                    && $param->var->name === $variableName
                    && $param->type instanceof Name) {
                    return $this->resolveClassNameFromString($param->type->toString(), $useStatements);
                }
            }
        }

        return null;
    }

    private function findVariableTypeFromDocBlocks(string $variableName, array $allNodes, array $useStatements): ?string
    {
        $nodeFinder = new NodeFinder();

        $methods = $nodeFinder->findInstanceOf($allNodes, ClassMethod::class);

        foreach ($methods as $method) {
            /** @var ClassMethod $method */
            $docComment = $method->getDocComment();
            if ($docComment) {
                $text = $docComment->getText();

                if (preg_match('/@var\s+([^\s]+)\s+\$' . preg_quote($variableName, '/') . '/', $text, $matches)) {
                    $type = trim($matches[1]);

                    return $this->resolveClassNameFromString($type, $useStatements);
                }
            }
        }

        return null;
    }

    private function resolveClassNameFromString(string $className, array $useStatements): string
    {
        if (!str_contains($className, '\\') && isset($useStatements[$className])) {
            return $useStatements[$className];
        }

        $parts = explode('\\', $className);
        $first = $parts[0];

        if (isset($useStatements[$first])) {
            $resolved = $useStatements[$first];
            if (count($parts) > 1) {
                $resolved .= '\\' . implode('\\', array_slice($parts, 1));
            }

            return $resolved;
        }

        return $className;
    }
}
