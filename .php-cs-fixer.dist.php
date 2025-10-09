<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

return
    (new Config())
        ->setCacheFile(__DIR__ . '/var/cache/.php_cs')
        ->setFinder(
            Finder::create()
                ->in([
                    __DIR__ . '/src',
                    __DIR__ . '/tests',
                ])
                ->append([
                    __FILE__,
                ])
                ->exclude([
                    __DIR__ . '/tests/mocks',
                ]),
        )
        ->setRules([
            '@PSR12' => true,
            '@PSR12:risky' => true,
            '@PHP83Migration' => true,
            '@PHP80Migration:risky' => true,
            '@PHPUnit84Migration:risky' => true,
            '@PhpCsFixer' => true,
            '@PhpCsFixer:risky' => true,
            'no_unused_imports' => true,
            'ordered_imports' => ['imports_order' => ['class', 'function', 'const']],
            'concat_space' => ['spacing' => 'one'],
            'cast_spaces' => ['space' => 'none'],
            'binary_operator_spaces' => [
                'default' => 'single_space',
                'operators' => [
                    '=' => 'single_space',
                    '=>' => 'single_space',
                ],
            ],
            'no_whitespace_before_comma_in_array' => true,
            'phpdoc_to_comment' => false,
            'phpdoc_separation' => false,
            'phpdoc_types_order' => ['null_adjustment' => 'always_last'],
            'phpdoc_align' => false,
            'phpdoc_scalar' => true,
            'phpdoc_trim' => true,
            'no_empty_statement' => true,
            'no_spaces_around_offset' => true,
            'phpdoc_var_annotation_correct_order' => true,
            'declare_strict_types' => true,
            'strict_comparison' => true,
            'operator_linebreak' => false,
            'global_namespace_import' => ['import_classes' => true, 'import_constants' => true, 'import_functions' => true],
            'blank_line_before_statement' => true,
            'multiline_whitespace_before_semicolons' => ['strategy' => 'no_multi_line'],
            'fopen_flags' => ['b_mode' => true],
            'php_unit_strict' => false,
            'php_unit_test_class_requires_covers' => false,
            'php_unit_test_case_static_method_calls' => ['call_type' => 'self'],
            'php_unit_method_casing' => ['case' => 'snake_case'],
            'yoda_style' => true,
            'final_class' => true,
            'final_public_method_for_abstract_class' => true,
            'self_static_accessor' => true,
            'static_lambda' => true,
            'heredoc_to_nowdoc' => false,
            'clean_namespace' => true,
            'trailing_comma_in_multiline' => [
                'elements' => ['arrays', 'match', 'arguments', 'parameters'],
            ],
            'array_indentation' => true,
            'whitespace_after_comma_in_array' => true,
            'trim_array_spaces' => true,
            'no_whitespace_in_blank_line' => true,
        ]);
