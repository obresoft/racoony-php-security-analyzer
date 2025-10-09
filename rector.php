<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\DeadCode\Rector\Property\RemoveUselessVarTagRector;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->parallel();
    $rectorConfig->paths(
        [
            __DIR__ . '/src',
        ]
    );

    $rectorConfig->sets(
        [
            LevelSetList::UP_TO_PHP_83,
            SetList::CODE_QUALITY,
            SetList::EARLY_RETURN,
            SetList::CODING_STYLE,
            SetList::DEAD_CODE,
        ]
    );

    $rectorConfig->skip(
        [
            RemoveUselessVarTagRector::class,
        ]
    );
};