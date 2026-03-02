# CWE-915: Laravel Mass Assignment From Request

## Summary

This rule detects **potential Laravel mass assignment** when user-controlled request data is passed into Eloquent write operations without sufficient protection.

It flags cases like `Model::create($request->all())`, `update($request->input())`, `fill($request->all())`, `forceFill($request->all())`, `firstOrCreate($request->all())`, `upsert($request->all(), ...)`, etc.

Mapped to:

**CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes**

---

## Rule implementation overview

This rule is implemented by the `LaravelMassAssignmentRule::class`.

The rule performs the following checks:

### 1. Model Write Sink Detection
Triggers only when the current call is a Laravel **model write method** (create/update/fill/upsert/firstOrCreate/etc.) and the call has arguments.

### 2. Mass Assignment Protection Check
Skips reporting if the target model has mass assignment protection configured (e.g. `fillable` / `guarded`) according to the model metadata.

### 3. Request Source Tracking
Inspects the write-method arguments and reports when:
- the value originates from Laravel `Request` methods (`all()`, `input()`, `except()`, `json()->all()`, etc.), and
- the data is **not** coming from validated sources (e.g. `$request->validate(...)` result or `$request->validated()`)

---

## Why This Matters

Mass assignment allows attackers to submit extra attributes that the application did not intend to update, for example:

- privilege flags (`is_admin`, `role`)
- ownership fields (`user_id`, `tenant_id`)
- security-related attributes (`is_active`, `email_verified_at`)

If the model is not properly protected and untrusted input is passed directly, attackers can modify sensitive attributes.

---

## What the Rule Does

The rule reports a vulnerability when:

- An Eloquent write operation is called with arguments, and
- The model lacks mass assignment protection, and
- User-controlled request data is passed directly (or through wrappers like `array_merge(...)`), and
- The data is not explicitly validated / safely mapped
