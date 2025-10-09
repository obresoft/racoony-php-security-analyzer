<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule;

use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Insight\Recommendation;
use Obresoft\Racoony\Insight\Vulnerability;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use PhpParser\Node;
use ReflectionClass;
use RuntimeException;

use function is_callable;
use function sprintf;

abstract class AbstractRule
{
    /** @var Node[] */
    protected array $allNodes = [];

    protected ?ClassNameResolver $nameResolver = null;

    public function __construct(protected readonly string $file = '') {}

    final public function beforeTraverse(array $nodes): null
    {
        $this->allNodes = $nodes;

        $this->nameResolver = new ClassNameResolver($this->allNodes);

        $callback = $this->beforeCheck();

        if (is_callable($callback)) {
            $callback($this->allNodes);
        }

        return null;
    }

    protected function beforeCheck(): ?callable
    {
        return null;
    }

    protected function createInsight(string $type, string $message, int $line, string $severity = 'MEDIUM', ?string $ruleId = null, string $insight = Vulnerability::class): Insight
    {
        $cweList = $this->resolveCWEs();

        if (null !== $ruleId) {
            $cweInfo = $cweList[$ruleId] ?? null;

            if (null === $cweInfo) {
                throw new RuntimeException(sprintf('CWE with ID "%s" not found in attributes.', $ruleId));
            }

            $suffix = sprintf('[CWE-%s: %s] See: %s', $cweInfo['id'], $cweInfo['title'], $cweInfo['url']);
        } else {
            $suffix = implode(PHP_EOL, array_map(
                static fn ($cwe) => sprintf('[CWE-%s: %s] See: %s', $cwe['id'], $cwe['title'], $cwe['url']),
                $cweList,
            ));
        }

        if (Recommendation::class === $insight) {
            return new Recommendation(
                $this->file,
                $type,
                $message . PHP_EOL . $suffix,
                $line,
            );
        }

        return new Vulnerability(
            $this->file,
            $type,
            $message . PHP_EOL . $suffix,
            $line,
            $severity,
        );
    }

    /**
     * @return array<string, array{id: string, title: string, url: string}>
     */
    private function resolveCWEs(): array
    {
        $refClass = new ReflectionClass(static::class);
        $attributes = $refClass->getAttributes(CWE::class);

        if ($refClass->isSubclassOf(self::class) && [] === $attributes) {
            throw new RuntimeException(sprintf(
                'Class "%s" extends AbstractRule but is missing the required #[CWE(...)] attribute.',
                static::class,
            ));
        }

        $cweList = [];
        foreach ($attributes as $attribute) {
            /** @var CWE $cweInstance */
            $cweInstance = $attribute->newInstance();
            $cweList[$cweInstance->id] = [
                'id' => $cweInstance->id,
                'title' => $cweInstance->title,
                'url' => $cweInstance->url,
            ];
        }

        return $cweList;
    }
}
