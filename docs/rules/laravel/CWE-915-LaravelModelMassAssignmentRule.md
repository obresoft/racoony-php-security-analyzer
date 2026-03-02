# CWE-915: Laravel Model Mass Assignment Misconfiguration

## Summary

This rule detects Laravel Eloquent models that are **misconfigured to allow mass assignment of unintended attributes**.

It flags models that effectively permit assigning **any attribute** via request-driven write operations because the model does not enforce a safe whitelist.

Mapped to:

**CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes**

---

## Rule implementation overview

This rule is implemented by the `LaravelModelMassAssignmentRule::class`.

The rule performs the following checks:

### 1. Laravel Model Detection
Runs only on class definitions that are identified as Laravel Eloquent models.

### 2. Dangerous Mass Assignment Configuration Detection
Reports a vulnerability when either condition is true:

- `$guarded = []` is set **and** there is no `$fillable` whitelist  
  (model is fully open for mass assignment)

- `$fillable` contains wildcard selection (`*` or `table.*`)  
  (model effectively whitelists all attributes)

---

## Why This Matters

If a model allows mass assignment of all attributes, attackers may be able to submit extra fields and modify sensitive attributes such as:

- authorization flags (`is_admin`, `role`)
- ownership fields (`user_id`, `tenant_id`)
- security-related state (`is_active`, `email_verified_at`)

Even if controller code “looks safe”, an overly permissive model configuration increases the blast radius of mistakes.

---

## What the Rule Does

The rule reports a vulnerability when:

- The class is a Laravel model, and
- The model configuration allows unrestricted assignment via:
    - `$guarded = []` without `$fillable`, or
    - `$fillable` wildcard selection (`*` / `table.*`)
