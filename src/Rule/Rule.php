<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Insight\Insight;

interface Rule
{
    /**
     * Check a node and return any insights found.
     *
     * @param AnalysisContext $context The analysis context
     * @return Insight|list<Insight>|null The insight(s) found, or null if none
     */
    public function check(AnalysisContext $context): null|array|Insight;
}
