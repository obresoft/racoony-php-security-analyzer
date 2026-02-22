<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Command\Reporting;

use InvalidArgumentException;

use function sprintf;

final class ReportBuilder
{
    /**
     * @param array<string, Report> $reportersByFormat
     */
    public function __construct(private array $reportersByFormat) {}

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
