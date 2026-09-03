<?php

/**
 * PHP Sentinel example configuration.
 *
 * Copy this file to `.php-sentinel.php` in your project root and adjust the
 * options to suit your needs. Every key in this sample is optional; when a key
 * is omitted the corresponding default is used.
 *
 * Run `vendor/bin/sentinel scan . --config=.php-sentinel.php` to use it.
 *
 * @return array<string, mixed>
 */

return [
    // File extensions (without the leading dot) that should be scanned.
    'extensions' => ['php', 'phtml', 'inc'],

    // Paths (directories or file name fragments) that should be skipped.
    'ignore' => ['vendor', 'node_modules', '.git', 'storage', 'cache'],

    // Rule IDs that should be enabled. When omitted, all bundled rules are enabled.
    'rules' => [
        'SEC001', // SQL Injection
        'SEC002', // Cross-Site Scripting
        'SEC003', // Command Injection
        'SEC004', // File Inclusion
        'SEC005', // Unsafe File Upload
    ],

    // Rule IDs to disable. This is an alternative to listing only enabled rules.
    'disabled_rules' => [],

    // Minimum severity that is reported: INFO, LOW, MEDIUM, HIGH or CRITICAL.
    'severity' => 'INFO',

    // Output format: 'console' or 'json'.
    'format' => 'console',

    // Whether to show a progress indicator during the scan.
    'progress' => true,

    // Whether to print verbose/diagnostic output.
    'verbose' => false,
];
