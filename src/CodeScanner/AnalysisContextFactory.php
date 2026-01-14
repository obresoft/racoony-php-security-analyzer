<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\AnalyzerResolver;
use Obresoft\Racoony\Analyzer\FileIndex;
use Obresoft\Racoony\Analyzer\GlobalAnalyzerFactory;
use Obresoft\Racoony\Analyzer\Scope;
use Obresoft\Racoony\Analyzer\VariableAnalyzer;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;
use PhpParser\Node;
use RuntimeException;

use function count;
use function in_array;
use function is_array;

final class AnalysisContextFactory
{
    private ?FileIndex $fileIndex = null;

    private ?VariableAnalyzer $variableAnalyzerV2 = null;

    private ?GlobalAnalyzerFactory $globalAnalyzerFactory = null;

    /** @var list<Node> */
    private array $allNodes = [];

    /**
     * @param list<Node> $rootNodes
     */
    public function initializeForFile(array $rootNodes): void
    {
        $this->allNodes = $this->collectAllNodesIterative($rootNodes);
        $this->fileIndex = new FileIndex($this->allNodes);
        $this->variableAnalyzerV2 = new VariableAnalyzer($this->fileIndex);
        $this->globalAnalyzerFactory = new GlobalAnalyzerFactory();
    }

    public function createForNode(
        Node $node,
        ?ProjectDataFlowIndex $projectDataFlowIndex,
        ?ApplicationData $applicationData = null,
    ): AnalysisContext {
        if (in_array(null, [$this->fileIndex, $this->variableAnalyzerV2, $this->globalAnalyzerFactory], true)) {
            throw new RuntimeException(
                'AnalysisContextFactory must be initialized with initializeForFile() before use.',
            );
        }

        $scope = new Scope(
            $node,
            $this->allNodes,
            $this->variableAnalyzerV2,
        );

        $analyzerResolver = new AnalyzerResolver(
            $scope,
            $this->globalAnalyzerFactory,
            $projectDataFlowIndex,
        );

        return new AnalysisContext(
            $scope,
            $analyzerResolver,
            $projectDataFlowIndex,
            $applicationData,
        );
    }

    /**
     * @param list<Node> $nodes
     * @return list<Node>
     */
    private function collectAllNodesIterative(array $nodes): array
    {
        $flatNodes = [];
        $stack = $nodes;

        while ([] !== $stack) {
            /** @var Node $current */
            $current = array_pop($stack);
            $flatNodes[] = $current;

            foreach ($current->getSubNodeNames() as $subNodeName) {
                $child = $current->{$subNodeName};

                if ($child instanceof Node) {
                    $stack[] = $child;
                } elseif (is_array($child)) {
                    $length = count($child);
                    for ($i = 0; $i < $length; ++$i) {
                        $candidate = $child[$i] ?? null;
                        if ($candidate instanceof Node) {
                            $stack[] = $candidate;
                        }
                    }
                }
            }
        }

        return $flatNodes;
    }
}
