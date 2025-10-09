<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\DataFlow\ProjectDataFlowIndex;

final readonly class AnalysisContext
{
    public function __construct(
        public Scope $scope,
        public AnalyzerResolver $analyzerResolver,
        public ?ProjectDataFlowIndex $projectDataFlowIndex = null,
        public ?ApplicationData $applicationData = null,
    ) {}
}
