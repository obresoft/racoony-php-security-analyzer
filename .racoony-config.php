<?php

use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Config\RacoonyConfig;
use Obresoft\Racoony\Rule\RuleSet;

return (new RacoonyConfig())
    ->setPath(__DIR__ . '/var/laravel')
    ->setRules(['*'])
    ->setPackageRules([RuleSet::PHP, RuleSet::LARAVEL])
    ->setApplication(new ApplicationData('Laravel', "8"));
