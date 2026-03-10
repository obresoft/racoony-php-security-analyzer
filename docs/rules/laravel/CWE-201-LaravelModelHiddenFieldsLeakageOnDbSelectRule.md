# CWE-201: Laravel Model Hidden Fields Leakage on DB Select

## Summary

This rule detects cases where Laravel database queries may expose **model attributes marked as hidden** by selecting them directly from the database.

In Laravel, model-level `$hidden` attributes are excluded only when using Eloquent serialization. When using the DB facade (`DB::table()`), these protections are bypassed. Selecting hidden columns such as passwords or tokens may result in sensitive data being sent to responses, APIs, or views.

The rule also supports Racoony’s custom `#[SensitiveFieldsAttribute]`, which allows you to mark sensitive model fields explicitly for detection even when they are not defined in Laravel’s `$hidden` property.

---

## Rule implementation overview

This rule is implemented by the `LaravelModelHiddenFieldsLeakageOnDbSelectRule::class`.

The rule performs Laravel-aware static analysis of database queries built via the `DB` facade. It correlates database table usage with model metadata collected during project-wide analysis.

At a high level, the rule:

- Detects usage of Laravel’s `DB::table()` facade
- Resolves the target table name and alias
- Maps the table to a Laravel model using project data flow
- Extracts sensitive fields from either:
    - Laravel model `$hidden`
    - Racoony `#[SensitiveFieldsAttribute([...])]`
- Analyzes selected columns in the query
- Reports a vulnerability if hidden or sensitive attributes may be included in the result set

---

## Why this is a problem

Laravel’s `$hidden` property protects sensitive attributes only at the Eloquent serialization layer.

When queries are built using the DB facade:

- Model serialization rules are bypassed
- `$hidden` attributes are not automatically excluded
- Sensitive columns may be returned as raw query results

This can lead to:

- Password hashes being returned in API responses
- Tokens or secrets leaking to views
- Sensitive fields being logged or cached
- Accidental data exposure in production systems

The issue is especially dangerous when wildcard selects (`*`) or implicit selects are used.

---

## Background: Laravel `$hidden` attributes

Laravel models allow developers to hide sensitive attributes:

```php
class User extends Model
{
    protected $hidden = [
        'password',
        'remember_token',
    ];
}
These attributes are excluded when using Eloquent:

User::all();
```

However, when using the DB facade:
```php
DB::table('users')->get();
```

Laravel does not apply model-level protections.

---

## Racoony `SensitiveFieldsAttribute`

Racoony also supports explicitly marking sensitive fields with the `SensitiveFieldsAttribute`:
```php
    #[SensitiveFieldsAttribute(['password', 'remember_token', 'api_token'])]
    class User extends Model
    {
    } 
```

This is useful when:

- sensitive fields are not listed in `$hidden`
- the project uses custom exposure rules
- you want analyzer-only protection metadata without changing runtime serialization behavior

When present, the rule treats fields defined in `#[SensitiveFieldsAttribute]` as the **source of truth** for sensitive attributes.  
In this case Laravel `$hidden` is ignored.

If the attribute is not defined, the rule falls back to using the model’s `$hidden` property.

---

## What this rule detects

The rule reports an issue when all of the following are true:

- A database query is built using `DB::table()`
- The target table is associated with a Laravel model
- The model defines one or more sensitive fields via:
    - `$hidden`, or
    - `#[SensitiveFieldsAttribute(...)]`
- The query may include those fields via:
    - wildcard selection (`*` or `alias.*`)
    - explicit selection of sensitive fields
    - variable-based select fields resolving to sensitive columns
    - missing `select()` call (implicit select)

---

## Examples

❌ Noncompliant code example (wildcard select)
```php
DB::table('users as u')
    ->select('u.*')
    ->get();
```

The wildcard select includes all columns, including hidden attributes such as `password` and `remember_token`.

❌ Noncompliant example (implicit select)
```php
DB::table('users')->get();
```

Without an explicit `select()`, all columns are returned, including hidden or sensitive ones.

❌ Explicit hidden field selection
```php
DB::table('users')
    ->select(['id', 'password'])
    ->get();
```

Hidden attributes are directly selected and exposed.

❌ Variable-based selection
```php
$fields = ['id', 'password'];

DB::table('users')
    ->select($fields)
    ->get();
```
What the rule does NOT report
Tables without associated models
If no Laravel model with $hidden attributes is associated with the table, no issue is reported.

## Severity

**Medium**

This issue may lead to unintended disclosure of sensitive information but does not directly enable code execution.

---

## References

- CWE-201: Insertion of Sensitive Information Into Sent Data
- Laravel Documentation: Eloquent Serialization