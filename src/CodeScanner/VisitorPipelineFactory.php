<?php

declare(strict_types=1);

namespace Obresoft\Racoony\CodeScanner;

use PhpParser\NodeVisitor;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitor\ParentConnectingVisitor;

final class VisitorPipelineFactory
{
    /**
     * @return list<NodeVisitor>
     */
    public function createStandardVisitors(): array
    {
        return [
            new NameResolver(null, [
                'preserveOriginalNames' => true,
                'replaceNodes' => false,
            ]),
            new ParentConnectingVisitor(),
        ];
    }
}
