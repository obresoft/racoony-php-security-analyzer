<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Return_;

use function in_array;

/**
 * CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute.
 * @see https://cwe.mitre.org/data/definitions/614.html
 * The Secure attribute for sensitive cookies in HTTPS sessions is not set,
 * which could cause the user agent to send those cookies in plaintext over an HTTP session.
 *
 * CWE-1275: Sensitive Cookie with Improper SameSite Attribute
 * @see https://cwe.mitre.org/data/definitions/1275.html
 * The SameSite attribute for sensitive cookies is not set, or an insecure value is used.
 *
 * CWE-1004: The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.
 * @see https://cwe.mitre.org/data/definitions/1004.html
 * The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies.
 * Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate the risk associated with Cross-Site Scripting
 * (XSS) where an attacker's script code might attempt to read the contents of a cookie and exfiltrate information obtained.
 * When set, browsers that support the flag will not reveal the contents of the cookie to a third party via client-side script
 * executed via XSS.
 */
#[CWE('614', "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", 'https://cwe.mitre.org/data/definitions/614.html')]
#[CWE('1275', 'Sensitive Cookie with Improper SameSite Attribute', 'https://cwe.mitre.org/data/definitions/1275.html')]
#[CWE('1004', "Sensitive Cookie Without 'HttpOnly' Flag", 'https://cwe.mitre.org/data/definitions/1004.html')]
final class LaravelSetCookieSecurityRule extends AbstractRule implements Rule
{
    public function check(AnalysisContext $context): null|array|Insight
    {
        if (!str_contains($this->file, 'config/session.php')) {
            return null;
        }

        $node = $context->scope->node();

        if (!$node instanceof Return_ || !$node->expr instanceof Array_) {
            return null;
        }

        $config = [];

        foreach ($node->expr->items as $item) {
            if (!$item->key instanceof String_) {
                continue;
            }

            $key = strtolower($item->key->value);
            $config[$key] = $item->value;
        }

        if (!isset($config['http_only'])) {
            return $this->createInsight(
                CWE::CWE_1004,
                'Missing `http_only` flag in session cookie config',
                $node->getLine(),
                Severity::HIGH->value,
                CWE::CWE_1004,
            );
        }

        if ($config['http_only'] instanceof ConstFetch) {
            $value = strtolower($config['http_only']->name->toString());
            if ('true' !== $value) {
                return $this->createInsight(
                    CWE::CWE_1004,
                    '`http_only` should be `true` for secure cookies',
                    $node->getLine(),
                    Severity::HIGH->value,
                    CWE::CWE_1004,
                );
            }
        }

        if (!isset($config['secure'])) {
            return $this->createInsight(
                CWE::CWE_614,
                'Missing `secure` flag in session cookie config',
                $node->getLine(),
                Severity::HIGH->value,
                CWE::CWE_614,
            );
        }

        if ($config['secure'] instanceof ConstFetch) {
            $value = strtolower($config['secure']->name->toString());
            if ('true' !== $value) {
                return $this->createInsight(
                    CWE::CWE_614,
                    '`secure` should be `true` for HTTPS-only cookies',
                    $node->getLine(),
                    Severity::HIGH->value,
                    CWE::CWE_614,
                );
            }
        }

        if (!isset($config['same_site'])) {
            return $this->createInsight(
                CWE::CWE_1275,
                'Missing or insecure `same_site` flag in session cookie config',
                $node->getLine(),
                Severity::HIGH->value,
                CWE::CWE_1275,
            );
        }

        if ($config['same_site'] instanceof String_) {
            $value = strtolower($config['same_site']->value);
            if (!in_array($value, ['strict', 'lax'], true)) {
                return $this->createInsight(
                    CWE::CWE_1275,
                    '`same_site` should be `strict` or `lax`',
                    $node->getLine(),
                    Severity::HIGH->value,
                    CWE::CWE_1275,
                );
            }
        }

        return null;
    }
}
