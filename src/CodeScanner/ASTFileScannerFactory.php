<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\SourceCodeProvider;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;

final class ASTFileScannerFactory
{
    public static function create(SourceCodeProvider $sourceCodeProvider, ?ApplicationData $applicationData = null): ASTFileScanner
    {
        $parser = (new ParserFactory())->createForVersion(PhpVersion::fromString('8.3'));
        $visitorPipelineFactory = new VisitorPipelineFactory();
        $analysisContextFactory = new AnalysisContextFactory();
        $insightCollector = new InsightCollector();

        return new ASTFileScanner(
            $sourceCodeProvider,
            $parser,
            $visitorPipelineFactory,
            $analysisContextFactory,
            $insightCollector,
            $applicationData,
        );
    }
}

