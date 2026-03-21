<p align="center">
  <a href="https://packagist.org/packages/obresoft/racoony">
     <img src="https://img.shields.io/badge/version-0.1.0-blue?style=flat-square" alt="Project Version">
  </a>
  <a href="https://www.php.net/releases/8.3/en.php">
    <img src="https://img.shields.io/badge/php-%5E8.3-blue?style=flat-square" alt="PHP Version">
  </a>
  <a href="https://github.com/phpstan/phpstan">
    <img src="https://img.shields.io/badge/phpstan-level%203-brightgreen?style=flat-square" alt="PHPStan Level">
  </a>
</p>

# Racoony PHP Security Analyzer

Racoony PHP Security Analyzer is a **security-first static analysis tool** for PHP frameworks and their ecosystems (frameworks and libraries), with future plans to expand into **Symfony, WordPress**, and more.

Its goal is to **collect and analyze common code patterns that may lead to security vulnerabilities**, providing early detection before they reach production.

Racoony identifies risky constructs, insecure configurations, and misuses of framework features based on [CWE](https://cwe.mitre.org/) classifications, helping developers prevent common vulnerabilities and improve the overall security posture of their applications.


> ⚠️ **Disclaimer**:  
> This Software does not and cannot guarantee the complete security of any application.  
> It identifies code patterns and constructs that may indicate security risks or potential vulnerabilities,  
> but it cannot provide assurance of absolute protection against exploits or attacks.

---

<p align="center">
    <a href="#">
        <img src="./logo.png" title="Racoony PHP Security Analyzer" alt="Racoony PHP Security Analyzer">
    </a>
</p>

## 🚧 Project Status

- Racoony is currently **in active development** (pre-release stage).  
- We welcome **feedback, bug reports, and contributions** from the community to help shape the tool.
- **Current Version (initial preview):** `0.1.0`

---

## ✨ Features

Racoony comes with a growing set of security rules, aligned with CWE standards:

### Generic Rules
- **CWE-77**: Command injection via unsafe shell functions (`exec`, `system`, `shell_exec`, etc.)
- **CWE-94**: Code injection via `eval` or unsafe dynamic code execution
- **CWE-215**: Information exposure via debug functions (`var_dump`, `dd`, `print_r`, etc.)
- **CWE-502**: Deserialization of untrusted data via unsafe usage of `unserialize()` (PHP Object Injection)
- **CWE-532**: Missing `#[\SensitiveParameter]` attribute on sensitive function parameters
- **CWE-614 / CWE-1275 / CWE-1004**: Insecure cookie attributes (`Secure`, `SameSite`, `HttpOnly`)

### Laravel Rules
- **CWE-89**: SQL Injection (raw queries and unsafe query builder usage)
  - `LaravelColumnNameSqlInjectionRule`
  - `LaravelRawSqlInjectionRule`
- **CWE-94**: Insecure callable execution from `Request` (e.g., `call_user_func`)
- **CWE-315**: Sensitive cookies excluded from `EncryptCookies` middleware
- **CWE-352**: Missing CSRF middleware (`VerifyCsrfToken`)
- **CWE-601**: Open redirect vulnerabilities
- **CWE-614 / CWE-1275 / CWE-1004**: Insecure cookie handling inside Laravel
- **CWE-915**: Mass assignment vulnerabilities (models without `$fillable` or with unguarded properties)
- **CWE-915**: LaravelModelRequiresFillable rule (ensures `$fillable` is explicitly defined)

### Spatie Query Builder Rules
- **CWE-639**: Authorization bypass through user-controlled includes/fields (`allowedIncludes`, `allowedFields`)
- **CWE-89**: SQL Injection through `allowedSorts` / `defaultSort`

---

## 📌 Roadmap

- 🚧 Laravel & Laravel packages support
- 🚧 Symfony rules (planned)
- 🚧 WordPress plugin/theme rules (planned)
- 🚧 Continuous improvements of detection patterns and adding new vulnerability rule
---

## 🛠️ Installation

Install Racoony via Composer:

```bash
composer require obresoft/racoony --dev
```

## ⚙️ Configuration

In the root of your project, create a file **`.racoony-config.php`** with your configuration:

```php
<?php

use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Config\RacoonyConfig;
use Obresoft\Racoony\Rule\RuleSet;

return (new RacoonyConfig())
    ->setPath(__DIR__)
    ->setRules(['*']) // run all available rules
    // or select specific rule sets
    ->setPackageRules([
        RuleSet::PHP,
        RuleSet::LARAVEL,
    ]);
```

## 🖥️ Requirements

Minimum PHP version: 8.3

## ▶️ Usage
Run from project root (where .racoony-config.php is located):

./vendor/bin/racoony scan


## 🧭 Contribution & feedback

Racoony is in active development - your feedback and contributions are highly appreciated:

🐞 Bug reports and issues - open on GitHub 

💡 Rule proposals - describe pattern and CWE mapping


