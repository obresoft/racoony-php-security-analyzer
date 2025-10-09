<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final readonly class CWE
{
    public const string CWE_89 = 'CWE-89';

    public const string CWE_94 = 'CWE-94';

    public const string CWE_601 = 'CWE-601';

    public const string CWE_614 = '614';

    public const string CWE_639 = 'CWE-639';

    public const string CWE_915 = 'CWE-915';

    public const string CWE_315 = 'CWE-315';

    public const string CWE_352 = 'CWE-352';

    public const string CWE_532 = 'CWE-532';

    public const string CWE_1004 = '1004';

    public const string CWE_1275 = '1275';

    public function __construct(
        public string $id,
        public string $title,
        public string $url,
    ) {}
}
