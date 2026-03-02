# CWE-94: Laravel Insecure Callable Invocation From Request

## Summary

This rule detects cases where **user-controlled input from Laravel `Request` is used as a callable and invoked**, which may lead to **arbitrary code execution**.

Typical risky patterns include invoking a variable function, dynamic method name, or passing request-controlled callables into functions like `call_user_func()`.

Mapped to:

**CWE-94 — Improper Control of Generation of Code (Code Injection)**

---

## Rule implementation overview

This rule is implemented by the `LaravelInsecureCallableFromRequest::class`.

The rule performs the following checks:

### 1. Invocation Detection
Detects call-like execution patterns, including:
- Direct callable invocation (e.g. `$fn()`, `$callable()`, `$this->$method()`)
- Indirect invocation via call-like helpers:
    - `call_user_func()`
    - `call_user_func_array()`
    - `forward_static_call()`
    - `forward_static_call_array()`

### 2. Argument / Target Extraction
Extracts the invoked target (function name, callable variable, or callable array parts), including cases where the callable is an array like `[$class, $method]`.

### 3. Request Source Tracking
Resolves the callable back to its assigned value and reports an issue when the callable originates from Laravel Request methods (e.g. `Request::input()`, `Request::query()`, `Request::get()`), either:
- directly, or
- via variables previously assigned from Request input

---

## Why This Matters

When an attacker can control what callable is executed, they may be able to:

- invoke dangerous PHP functions
- call internal application methods not intended to be exposed
- trigger sensitive side effects
- achieve remote code execution depending on the environment and reachable callables
