# CWE-502: Deserialization of Untrusted Data

## Rule implementation overview

This rule is implemented by the ```UnserializeOnUntrustedDataRule::class```.

## Summary

This rule detects unsafe usage of PHP `unserialize()` on **untrusted or user-controlled data**.

In PHP, `unserialize()` is not a simple data parser. It reconstructs real PHP objects,
restores their internal state, and may automatically trigger object lifecycle methods.
When attacker-controlled input reaches `unserialize()`, this behavior can lead to
**PHP Object Injection** and severe security risks.

## Supported taint sources

The rule treats the following as untrusted sources:

PHP superglobals:
$_GET, $_POST, $_COOKIE, $_REQUEST, $_SERVER

Laravel request helpers and abstractions:

request()->input()

$request->input()

request()->cookie()

```php
$payloadFromUser = $_GET['data'];
unserialize($payloadFromUser);

```
or
```php
$payloadFromUser = $request->input('payload');
unserialize($payloadFromUser);

```
---

## Why this is a problem

Unlike formats such as JSON, PHP serialization restores **executable object graphs**.

When untrusted data is passed to `unserialize()`:

- Arbitrary existing classes can be instantiated
- Object properties (including private and protected ones) are populated directly
- Magic methods such as `__wakeup()` and `__destruct()` may be triggered automatically
- Existing application or framework code may execute unintentionally

No direct code injection (e.g. `eval`) is required.  
The attacker abuses **existing code paths and side effects**.

---

## Illustrative example (simplified)
```php
final class MessageFormatter
{
    public string $messagePrefix = 'INFO';
    public string $messageBody = 'default';

    public function format(): string
    {
        return '[' . $this->messagePrefix . '] ' . $this->messageBody;
    }
}

final class FileLogger
{
    public string $logFilePath = 'storage/logs/laravel.log';

    public function write(string $message): void
    {
        file_put_contents($this->logFilePath, $message . PHP_EOL, FILE_APPEND);
    }
}

final class BackgroundJob
{
    public MessageFormatter $formatter;
    public FileLogger $logger;

    public function __destruct()
    {
        $this->logger->write(
            $this->formatter->format()
        );
    }
}
```
If such objects are created via unserialize() instead of new,
the destructor may execute automatically at the end of the request,
triggering file IO without an explicit method call.

This demonstrates how object lifecycle + side effects
can be abused when deserialization is attacker-controlled.


## Full implementation and tests

The complete rule implementation and exhaustive test coverage are available here:

Rule class:
```src/Rule/PHP/UnserializeOnUntrustedDataRule.php```

Test suite (PHP & Laravel cases):
```tests/Rules/PHP/UnserializeOnUntrustedDataRuleTest.php```