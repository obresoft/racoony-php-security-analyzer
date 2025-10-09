<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\CWE;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\VariableArrayResolver;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayItem;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Scalar\String_;

use function array_key_exists;
use function in_array;
use function is_string;
use function strtolower;

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
final class SetCookieSecurityRule extends AbstractRule implements Rule
{
    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;

        if (!$scope->callAnalyzer()->isFunctionNamed('setcookie')) {
            return null;
        }

        $currentLineNumber = $scope->getLine();
        $argumentCount = $scope->callAnalyzer()->argCount();

        if ($argumentCount < 3) {
            return $this->createInsight(
                'SET_COOKIE_SECURE',
                'setcookie() without secure options array',
                $currentLineNumber,
                Severity::HIGH->value,
            );
        }

        $thirdArgumentExpression = $scope->callAnalyzer()->argExpr(2);

        if ($thirdArgumentExpression instanceof Array_) {
            $normalizedOptionMap = $this->extractOptionsArrayToMap($thirdArgumentExpression);

            return $this->validateOptionsArrayFlags($normalizedOptionMap, $currentLineNumber);
        }

        if ($thirdArgumentExpression instanceof Variable && is_string($thirdArgumentExpression->name)) {
            $variableArrayResolver = $context->analyzerResolver->get(VariableArrayResolver::class);
            $resolvedArrayLiteral = $variableArrayResolver->resolveArrayFromVariableAssignment($thirdArgumentExpression->name);
            if ($resolvedArrayLiteral instanceof Array_) {
                $normalizedOptionMap = $this->extractOptionsArrayToMap($resolvedArrayLiteral);
                $insight = $this->validateOptionsArrayFlags($normalizedOptionMap, $currentLineNumber);
                if (null !== $insight) {
                    return $insight;
                }
            }

            $incrementalOptionMap = $variableArrayResolver->resolveIncrementalArrayWrites($thirdArgumentExpression->name);
            if (null !== $incrementalOptionMap) {
                $insight = $this->validateOptionsArrayFlags($incrementalOptionMap, $currentLineNumber);
                if (null !== $insight) {
                    return $insight;
                }
            }
        }

        return null;
    }

    /**
     * @param array<string, Expr> $optionMap
     */
    private function validateOptionsArrayFlags(array $optionMap, int $lineNumber): ?Insight
    {
        $hasSecureFlag = array_key_exists('secure', $optionMap);
        $hasHttpOnlyFlag = array_key_exists('httponly', $optionMap);
        $hasSafeSameSite = false;

        if (array_key_exists('samesite', $optionMap)) {
            $sameSiteExpression = $optionMap['samesite'];
            if ($sameSiteExpression instanceof String_) {
                $sameSiteValue = strtolower($sameSiteExpression->value);
                if (in_array($sameSiteValue, ['strict', 'lax'], true)) {
                    $hasSafeSameSite = true;
                }
            }
        }

        if (!$hasSecureFlag) {
            return $this->createInsight(
                'SET_COOKIE_SECURE',
                'Missing `secure` flag in setcookie()',
                $lineNumber,
                Severity::HIGH->value,
                CWE::CWE_614,
            );
        }

        if (!$hasHttpOnlyFlag) {
            return $this->createInsight(
                'SET_COOKIE_HTTPONLY',
                'Missing `httponly` flag in setcookie()',
                $lineNumber,
                Severity::HIGH->value,
                CWE::CWE_1004,
            );
        }

        if (!$hasSafeSameSite) {
            return $this->createInsight(
                'SET_COOKIE_SAMESITE',
                'Missing or insecure `SameSite` flag in setcookie()',
                $lineNumber,
                Severity::MEDIUM->value,
                CWE::CWE_1275,
            );
        }

        return null;
    }

    /**
     * @return array<string, Expr>
     */
    private function extractOptionsArrayToMap(Array_ $optionsArrayExpression): array
    {
        $normalizedOptionMap = [];

        /** @var ArrayItem|null $arrayItem */
        foreach ($optionsArrayExpression->items ?? [] as $arrayItem) {
            $arrayKeyExpression = $arrayItem?->key;
            if ($arrayKeyExpression instanceof String_) {
                $normalizedOptionMap[strtolower($arrayKeyExpression->value)] = $arrayItem->value;
            }
        }

        return $normalizedOptionMap;
    }
}
