<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Config;

use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Rule\Rule;
use Obresoft\Racoony\Rule\RuleSet;
use Ramsey\Collection\Set;
use Webmozart\Assert\Assert;

use function in_array;

final class RacoonyConfig implements Config
{
    /** @var list<non-empty-string> */
    private array $paths = [];

    /** @var Set<class-string<Rule>> */
    private Set $rules;

    /** @var Set<class-string<Rule>> */
    private Set $removedRules;

    private ?ApplicationData $application = null;

    private Severity $failOn = Severity::LOW;

    public function __construct()
    {
        $this->rules = new Set('string');
        $this->removedRules = new Set('string');
    }

    /** @param non-empty-string $path */
    public function setPath(string $path): self
    {
        Assert::directory($path);
        $this->paths[] = $path;

        return $this;
    }

    public function getRootPath(): string
    {
        return (string)getcwd();
    }

    /** @return list<non-empty-string> */
    public function getPaths(): array
    {
        return $this->paths;
    }

    /** @param list<"*"|class-string<Rule>> $rules */
    public function setRules(array $rules): self
    {
        if (in_array('*', $rules, true)) {
            $this->addRulesToCollection($this->rules, RuleSet::getPackage(RuleSet::ALL));

            return $this;
        }

        $this->addRulesToCollection($this->rules, $rules);

        return $this;
    }

    /** @param list<RuleSet> $packages */
    public function setPackageRules(array $packages): self
    {
        foreach ($packages as $package) {
            Assert::isAOf($package, RuleSet::class);
            $this->addRulesToCollection($this->rules, RuleSet::getPackage($package));
        }

        return $this;
    }

    /** @return list<class-string<Rule>> */
    public function getRules(): array
    {
        if ($this->removedRules->isEmpty()) {
            return array_values($this->rules->toArray());
        }

        return array_values(array_diff($this->rules->toArray(), $this->removedRules->toArray()));
    }

    /** @param list<class-string<Rule>> $rules */
    public function removeRules(array $rules): self
    {
        $this->addRulesToCollection($this->removedRules, $rules);

        return $this;
    }

    public function setApplication(ApplicationData $application): self
    {
        $this->application = $application;

        return $this;
    }

    public function getApplication(): ?ApplicationData
    {
        return $this->application;
    }

    public function setFailOn(Severity $failOn): self
    {
        $this->failOn = $failOn;

        return $this;
    }

    public function getFailOn(): Severity
    {
        return $this->failOn;
    }

    /**
     * @param Set<class-string<Rule>> $collection
     * @param list<class-string<Rule>> $rules
     */
    private function addRulesToCollection(Set $collection, array $rules): void
    {
        foreach ($rules as $rule) {
            Assert::classExists($rule);
            Assert::isAOf($rule, Rule::class);

            $collection->add($rule);
        }
    }
}
