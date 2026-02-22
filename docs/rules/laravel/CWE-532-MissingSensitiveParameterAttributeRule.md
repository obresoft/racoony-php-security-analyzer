# CWE-532: Missing `#[\SensitiveParameter]` Attribute on Sensitive Parameters

## Summary

This rule detects function, method, and closure parameters that **likely contain sensitive data** but are **not marked with PHP’s `#[\SensitiveParameter]` attribute**.

In PHP 8.2+, the `#[\SensitiveParameter]` attribute prevents sensitive values from being exposed in stack traces, error messages, and logs. When this attribute is missing, confidential data such as passwords, tokens, or API keys may be unintentionally leaked during error handling or debugging.

---

## Rule implementation overview

This rule is implemented by the `MissingSensitiveParameterAttributeRule::class` class.

The rule analyzes **parameter declarations** during static analysis and applies a **name-based heuristic** to identify parameters that are likely to hold sensitive data.

At a high level, the rule:

- Inspects function, method, and closure parameters
- Checks whether the parameter has the `#[\SensitiveParameter]` attribute
- Applies a heuristic based on the parameter name
- Reports a low-severity issue when a sensitive parameter is not protected

The analysis is static and does not require control-flow or data-flow tracking.

---

## Why this is a problem

When an exception occurs, PHP may include **function arguments and their values** in stack traces. These traces are often:

- written to log files
- collected by error monitoring systems
- accessible to developers, operators, or third parties

If sensitive parameters are not explicitly marked:

- passwords may appear in logs
- API tokens may be stored in error tracking systems
- secrets may be retained longer than intended
- compliance requirements may be violated

This risk increases in production environments where logs are centralized and retained.

---

## PHP 8.2 background: `#[\SensitiveParameter]`

PHP 8.2 introduced the `#[\SensitiveParameter]` attribute to prevent sensitive parameter values from being exposed in stack traces.

```php
function login(#[\SensitiveParameter] string $password): void {}
```
When applied, PHP replaces the actual value with a placeholder in stack traces, reducing the risk of accidental leakage.

What this rule detects

The rule reports an issue when all of the following conditions are met:

The analyzed node is a parameter of a function, method, or closure

The parameter does not have the #[\SensitiveParameter] attribute

The parameter name matches a known sensitive identifier

Examples
❌ Noncompliant code example
```php 
function login(string $password, string $email): void {}
```

Why this is a problem

The $password parameter likely contains sensitive data but is not protected from appearing in stack traces.

✅ Compliant solution
```php 
function login(#[\SensitiveParameter] string $password, string $email): void {}
```

❌ Class method without attribute
```php 
final class AuthController {
    public function setToken(string $apiToken): void {}
}
```

❌ Closure parameter
```php  
$handler = function (string $secret): void {};
```

Closures are analyzed in the same way as functions and methods.

❌ Attribute on function, but not on parameter
#[\Deprecated]
function legacy(string $secret): void {}


Attributes applied to the function itself do not protect parameter values.
The parameter must be explicitly marked.

✅ Compliant example with imported attribute
```php
use SensitiveParameter;

function rotate(#[SensitiveParameter] string $token): void {}
```

What this rule does NOT report
Non-sensitive parameters
```php
function updateEmail(string $email): void {}
 ```

Parameters whose names do not match sensitive heuristics are ignored.

Parameters already marked as sensitive
```php 
function login(#[\SensitiveParameter] string $password): void {}
```

No issue is reported when the attribute is present.
Severity: Low

This issue does not directly enable exploitation but may lead to sensitive data exposure through logs and stack traces.
References

CWE-532: Insertion of Sensitive Information into Log File
https://cwe.mitre.org/data/definitions/532.html

PHP Manual: SensitiveParameter
https://www.php.net/manual/en/class.sensitiveparameter.php

Medium article: PHP SensitiveParameter: A Hidden Shield Against Credential Leaks
https://medium.com/p/2a0233518022
