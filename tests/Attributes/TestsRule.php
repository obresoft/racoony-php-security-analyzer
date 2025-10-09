<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests\Attributes;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS)]
final class TestsRule
{
    public function __construct(public string $ruleClass) {}
}
