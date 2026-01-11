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
    /** @var array<string> */
    private array $path = [];

    /** @var array<class-string<Rule>> */
    private array $rules = [];

    private ?ApplicationData $application = null;

    private Severity $failOn = Severity::LOW;

    /**
     * @param non-empty-string $path
     */
    public function setPath(string $path): self
    {
        Assert::directory($path);

        $this->path[] = $path;

        return $this;
    }

    public function getRootPath(): string
    {
        return $this->path[0] ?? getcwd();
    }

    /** @return array<string> */
    public function getPath(): array
    {
        return $this->path;
    }

    public function setRules(array $rules): self
    {
        if (in_array('*', $rules, true)) {
            $this->rules = RuleSet::getPackage(RuleSet::ALL);

            return $this;
        }

        $newRules = new Set('string');
        foreach ($this->rules as $rule) {
            $newRules->add($rule);
        }

        foreach ($rules as $rule) {
            Assert::classExists($rule);
            Assert::isAOf($rule, Rule::class);
            /** @var class-string<Rule> $rule */
            $newRules->add($rule);
        }

        $this->rules = array_values($newRules->toArray());

        return $this;
    }

    /**
     * Set rules by package name (e.g., 'php', 'laravel', etc.).
     *
     * @param array<RuleSet> $packages
     */
    public function setPackageRules(array $packages): self
    {
        /** @var Set<class-string<Rule>> $rules */
        $rules = new Set('string');
        foreach ($this->rules as $rule) {
            $rules->add($rule);
        }

        foreach ($packages as $package) {
            Assert::isAOf($package, RuleSet::class);

            /** @var list<class-string<Rule>> $packageRules */
            $packageRules = RuleSet::getPackage($package);

            foreach ($packageRules as $rule) {
                Assert::classExists($rule);
                Assert::isAOf($rule, Rule::class);
                $rules->add($rule);
            }
        }

        $this->rules = array_values($rules->toArray());

        return $this;
    }

    /** @return array<class-string<Rule>> */
    public function getRules(): array
    {
        return $this->rules;
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
}
