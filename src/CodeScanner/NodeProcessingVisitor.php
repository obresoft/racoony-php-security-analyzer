<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\Rule;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

use function is_array;

final class NodeProcessingVisitor extends NodeVisitorAbstract
{
    public function __construct(
        private readonly Rule $rule,
        private readonly AnalysisContextFactory $analysisContextFactory,
        private readonly ?ProjectDataFlowIndex $projectDataFlowIndex,
        private readonly InsightCollector $insightCollector,
        private readonly ?ApplicationData $applicationData = null,
    ) {}

    /**
     * @param list<Node> $nodes
     */
    public function beforeTraverse(array $nodes): null
    {
        $this->analysisContextFactory->initializeForFile($nodes);

        if (method_exists($this->rule, 'beforeTraverse')) {
            /** @var callable $callable */
            $callable = [$this->rule, 'beforeTraverse'];
            $callable($nodes);
        }

        return null;
    }

    public function enterNode(Node $node): null
    {
        $analysisContext = $this->analysisContextFactory->createForNode(
            $node,
            $this->projectDataFlowIndex,
            $this->applicationData,
        );

        $maybeInsight = $this->rule->check($analysisContext);

        if ($maybeInsight instanceof Insight) {
            $this->insightCollector->add($maybeInsight);
        } elseif (is_array($maybeInsight)) {
            foreach ($maybeInsight as $insight) {
                if ($insight instanceof Insight) {
                    $this->insightCollector->add($insight);
                }
            }
        }

        return null;
    }
}
