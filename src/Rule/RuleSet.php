<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Rule;

use Obresoft\Racoony\Rule\CWE\CodeInjectionRule;
use Obresoft\Racoony\Rule\CWE\CommandInjectionRule;
use Obresoft\Racoony\Rule\CWE\DebugFunctionExposureRule;
use Obresoft\Racoony\Rule\CWE\SetCookieSecurityRule;
use Obresoft\Racoony\Rule\Laravel\LaravelColumnNameSqlInjectionRule;
use Obresoft\Racoony\Rule\Laravel\LaravelCrossSiteRequestForgeryCsrf;
use Obresoft\Racoony\Rule\Laravel\LaravelInsecureCallableFromRequest;
use Obresoft\Racoony\Rule\Laravel\LaravelMassAssignmentRule;
use Obresoft\Racoony\Rule\Laravel\LaravelModelMassAssignmentRule;
use Obresoft\Racoony\Rule\Laravel\LaravelOpenRedirectRule;
use Obresoft\Racoony\Rule\Laravel\LaravelRawSqlInjectionRule;
use Obresoft\Racoony\Rule\Laravel\LaravelSensitiveCookieExemptions;
use Obresoft\Racoony\Rule\Laravel\LaravelSensitiveCookieInformation;
use Obresoft\Racoony\Rule\Laravel\LaravelSetCookieSecurityRule;
use Obresoft\Racoony\Rule\Laravel\Packages\SpatieQueryBuilder\SpatieQueryBuilderAuthorizationBypassRule;
use Obresoft\Racoony\Rule\Laravel\Packages\SpatieQueryBuilder\SpatieQueryBuilderSqlInjectionRule;
use Obresoft\Racoony\Rule\PHP\MissingSensitiveParameterAttributeRule;

enum RuleSet: string
{
    case ALL = '*';
    case PHP = 'php';
    case LARAVEL = 'laravel';

    /** @return list<class-string<Rule>> */
    public static function getPackage(self $value): array
    {
        return match ($value) {
            self::ALL => self::allPackage(),
            self::PHP => self::php(),
            self::LARAVEL => self::laravel(),
        };
    }

    /** @return list<class-string<Rule>> */
    private static function allPackage(): array
    {
        return [...self::php(), ...self::laravel()];
    }

    /** @return list<class-string<Rule>> */
    private static function php(): array
    {
        return [
            DebugFunctionExposureRule::class,
            SetCookieSecurityRule::class,
            CommandInjectionRule::class,
            CodeInjectionRule::class,
            MissingSensitiveParameterAttributeRule::class,
        ];
    }

    /** @return list<class-string<Rule>> */
    private static function laravel(): array
    {
        return [
            LaravelSetCookieSecurityRule::class,
            LaravelModelMassAssignmentRule::class,
            LaravelOpenRedirectRule::class,
            LaravelMassAssignmentRule::class,
            LaravelSensitiveCookieInformation::class,
            LaravelCrossSiteRequestForgeryCsrf::class,
            LaravelSensitiveCookieExemptions::class,
            LaravelInsecureCallableFromRequest::class,
            LaravelColumnNameSqlInjectionRule::class,
            LaravelRawSqlInjectionRule::class,
            ...self::laravelSpatieQueryBuilder(),
        ];
    }

    /** @return list<class-string<Rule>> */
    private static function laravelSpatieQueryBuilder(): array
    {
        return [
            SpatieQueryBuilderAuthorizationBypassRule::class,
            SpatieQueryBuilderSqlInjectionRule::class,
        ];
    }
}
