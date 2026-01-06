<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command\Reporting;

use InvalidArgumentException;

use function sprintf;

final class ReportBuilder
{
    /** @var array<string, Report> */
    private array $reportersByFormat;

    /**
     * @param array<string, Report> $reportersByFormat
     */
    public function __construct(array $reportersByFormat)
    {
        $this->reportersByFormat = $reportersByFormat;
    }

    public function build(string $format): Report
    {
        $normalizedFormat = strtolower(trim($format));

        if (!isset($this->reportersByFormat[$normalizedFormat])) {
            throw new InvalidArgumentException(sprintf(
                'Unknown report format "%s". Allowed: %s',
                $format,
                implode(', ', array_keys($this->reportersByFormat)),
            ));
        }

        return $this->reportersByFormat[$normalizedFormat];
    }
}
