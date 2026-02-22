# Racoony Configuration

`RacoonyConfig` is the main configuration object used to control what Racoony scans and which security rules are enabled.

## Overview

`Obresoft\Racoony\Config\RacoonyConfig`

Responsibilities:

- Define scan target paths
- Enable rules explicitly or by package (`RuleSet`)
- Remove specific rules even after enabling `*`
- Provide application metadata (framework + version)
- Configure failure threshold (`Severity`)

---

## API Reference

### setPath(string $path): self

```php
$config->setPath(__DIR__ . '/src');
```

Adds a directory path to scan.
Multiple calls append multiple paths

### setRules(array $rules): self

Enable rules explicitly.

Behavior:

If "*" is present → loads RuleSet::ALL.
Otherwise adds provided rule classes

Must implement Rule Interface


```php
$config->setRules(['*']);
```

```php
$config->setRules([
    UnserializeOnUntrustedDataRule::class,
]);
```

### setPackageRules(array $packages): self

Enable rule packages.

```php
$config->setPackageRules([
    RuleSet::PHP,
    RuleSet::LARAVEL
]);
```

Note:

If you call:

```php
$config->setRules(['*']);
```

Then setPackageRules() becomes redundant because RuleSet::ALL already includes everything.

### removeRules(array $rules): self

```php
$config
    ->setRules(['*'])
    ->removeRules([
        LaravelOpenRedirectRule::class,
    ]);
```


### setFailOn(Severity $failOn): self

```php
$config->setFailOn(Severity::HIGH);
```

## Full Example
```php
<?php

use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Config\RacoonyConfig;
use Obresoft\Racoony\Rule\RuleSet;

return (new RacoonyConfig())
    ->setPath(__DIR__ . '/var/examples')
    ->setRules(['*'])
    ->setPackageRules([RuleSet::PHP, RuleSet::LARAVEL])
    ->setApplication(new ApplicationData('Laravel', '8'));

```