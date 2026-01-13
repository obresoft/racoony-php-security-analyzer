<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\DataFlow\ProjectDataFlow;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\Rule;
use Obresoft\Racoony\SourceCodeProvider;
use PhpParser\Error as PhpParserError;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\Parser;

/**
 * @implements Scanner<Rule>
 */
final class ASTFileScanner implements Scanner
{
    private ?ProjectDataFlow $projectDataFlowIndex = null;

    public function __construct(
        private readonly SourceCodeProvider $sourceCodeProvider,
        private readonly Parser $phpParser,
        private readonly VisitorPipelineFactory $visitorPipelineFactory,
        private readonly AnalysisContextFactory $analysisContextFactory,
        private readonly InsightCollector $insightCollector,
        private ?ApplicationData $applicationData = null,
    ) {}

    public function withProjectDataFlowIndex(ProjectDataFlow $index): self
    {
        $clone = clone $this;
        $clone->projectDataFlowIndex = $index;

        return $clone;
    }

    /**
     * @return list<Insight>
     */
    public function scan(string $filePath, Rule $rule): array
    {
        $sourceCode = $this->sourceCodeProvider->read($filePath);

        try {
            /** @var list<Stmt>|null $ast */
            $ast = $this->phpParser->parse($sourceCode);
        } catch (PhpParserError $phpParserError) {
            throw FileParsingException::fromPhpParserError($filePath, $phpParserError);
        }

        if (null === $ast) {
            return [];
        }

        $this->insightCollector->reset();
        $nodeTraverser = new NodeTraverser();

        foreach ($this->visitorPipelineFactory->createStandardVisitors() as $visitor) {
            $nodeTraverser->addVisitor($visitor);
        }

        $nodeTraverser->addVisitor(
            new NodeProcessingVisitor(
                $rule,
                $this->analysisContextFactory,
                $this->projectDataFlowIndex,
                $this->insightCollector,
                $this->applicationData,
            ),
        );

        $nodeTraverser->traverse($ast);

        return $this->insightCollector->all();
    }
}
