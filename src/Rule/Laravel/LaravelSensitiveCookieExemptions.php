<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule\Laravel;

use Obresoft\Racoony\Analyzer\AnalysisContext;
use Obresoft\Racoony\Analyzer\Node\ClassAnalyzer;
use Obresoft\Racoony\Attribute\CWE;
use Obresoft\Racoony\Enum\Severity;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\Resolver\ClassNameResolver;
use Obresoft\Racoony\Rule\AbstractRule;
use Obresoft\Racoony\Rule\Rule;
use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;

use function in_array;
use function sprintf;

#[CWE('315', 'Cleartext Storage of Sensitive Information in a Cookie', 'https://cwe.mitre.org/data/definitions/315.html')]
final class LaravelSensitiveCookieExemptions extends AbstractRule implements Rule
{
    private const string MESSAGE = 'Sensitive cookie (%s) is excluded from encryption via $except in EncryptCookies. This may expose or allow tampering of session or token data.';

    /**
     * @var list<string>
     */
    private const array ENCRYPT_COOKIES_CLASSES = [
        'App\Http\Middleware\EncryptCookies',
        'Illuminate\Cookie\Middleware\EncryptCookies',
    ];

    /**
     * @var list<string>
     */
    private const array SENSITIVE_EXACT = [
        'session',
        'laravel_session',
        'remember_me',
        'remember_token',
        'xsrf-token',
        'XSRF-TOKEN',
        'csrf_token',
        'CSRF-TOKEN',
        'php_session',
        'PHPSESSID',
        'remember_web',
        'password_reset_token',
        'verification_token',
        'two_factor_token',
    ];

    /**
     * @var list<string>
     */
    private const array SENSITIVE_REGEX = [
        '/^remember(_web)?(_.*)?$/i',
        '/(^|_)access_token($|_)/i',
        '/(^|_)refresh_token($|_)/i',
        '/(^|_)id_token($|_)/i',
        '/(^|_)api_token($|_)/i',
        '/(^|_)jwt($|_)/i',
        '/(^|_)session($|_)/i',
        '/(^|_)xsrf(_)?token($|_)?/i',
        '/(^|_)csrf(_)?token($|_)?/i',
        '/^remember(?:_.*)?$/i',
    ];

    public function check(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;

        if ($context->applicationData->frameworkVersion < '11' && $scope->isClassCall()) {
            return $this->checkLaravelLessThan11($context);
        }

        return $this->checkLaravelGraterThan10($context);
    }

    public function checkLaravelLessThan11(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;
        /** @var Class_ $node */
        $node = $scope->node();
        $classAnalyzer = new ClassAnalyzer();
        $classData = $classAnalyzer->analyzeClass($node);
        $classNameResolver = new ClassNameResolver($scope->getNodes());

        if (!isset($classData['extends']) || !isset($classData['name'])) {
            return null;
        }

        $parentClass = $classNameResolver->resolveClassName($classData['extends']);
        $isEncryptCookies = in_array(
            $classNameResolver->resolveClassName($classData['name']),
            self::ENCRYPT_COOKIES_CLASSES,
            true,
        )
            || in_array($parentClass, self::ENCRYPT_COOKIES_CLASSES, true);

        if (!$isEncryptCookies) {
            return null;
        }

        foreach ($classAnalyzer->analyzeProperties($node) as $propertyData) {
            if ('except' !== $propertyData['name']) {
                continue;
            }

            $cookieNames = $this->extractExcludeStringsRecursively($propertyData['value']);

            return $this->detectSensitiveExemptions($cookieNames, $propertyData['line']);
        }

        return null;
    }

    public function checkLaravelGraterThan10(AnalysisContext $context): null|array|Insight
    {
        $scope = $context->scope;
        if (!str_contains($this->file, 'bootstrap/app.php')) {
            return null;
        }

        if (!$scope->callAnalyzer()->isMethodNamed('encryptCookies')) {
            return null;
        }

        foreach ($scope->callAnalyzer()->argScopes() as $argScope) {
            if ($argScope->arrayAnalyzer()->isArray()) {
                foreach ($argScope->arrayAnalyzer()->getArrayValueScopesRecursively() as $arrayValue) {
                    return $this->detectSensitiveExemptions([$arrayValue->stringValue()], $argScope->getLine());
                }
            }

            if ($argScope->isVariable()) {
                $variableFacts = $scope->analyzeVariable($argScope->nameAsString());

                foreach ($variableFacts as $variableFact) {
                    return $this->detectSensitiveExemptions([$variableFact->nameOrValue], $variableFact->line);
                }
            }
        }

        return null;
    }

    private function detectSensitiveExemptions(array $cookieNames, int $line): array
    {
        $violations = [];

        foreach ($cookieNames as $cookieName) {
            $normalized = $cookieName;

            if (in_array($normalized, self::SENSITIVE_EXACT, true)) {
                $violations[] = $this->report($line, $cookieName);

                continue;
            }

            foreach (self::SENSITIVE_REGEX as $pattern) {
                if (1 === preg_match($pattern, $normalized)) {
                    $violations[] = $this->report($line, $cookieName);

                    break;
                }
            }
        }

        return $violations;
    }

    /**
     * @return list<string>
     */
    private function extractExcludeStringsRecursively(mixed $value): array
    {
        $node = $value instanceof Node ? $value : ($value['node'] ?? null);

        if ($node instanceof Array_) {
            $result = [];
            foreach ($node->items ?? [] as $item) {
                if (null !== $item) {
                    $result = array_merge($result, $this->extractExcludeStringsRecursively($item->value));
                }
            }

            return $result;
        }

        if ($node instanceof String_) {
            return [$node->value];
        }

        return [];
    }

    private function report(int $line, string $cookieName): Insight
    {
        return $this->createInsight(
            CWE::CWE_315,
            sprintf(self::MESSAGE, $cookieName),
            $line,
            Severity::HIGH->value,
        );
    }
}
