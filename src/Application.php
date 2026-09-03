<?php

declare(strict_types=1);

namespace PhpSentinel;

use PhpSentinel\Command\ScanCommand;
use PhpSentinel\Config\ConfigurationLoader;
use PhpSentinel\Parser\PhpParser;
use PhpSentinel\Report\Report;
use PhpSentinel\Rules\RuleRegistry;
use PhpSentinel\Scanner\FileScanner;
use PhpSentinel\Scanner\Scanner;
use Symfony\Component\Console\Application as SymfonyApplication;

/**
 * Builds and configures the Symfony Console Application that hosts all
 * PHP Sentinel commands.
 */
final class Application
{
    public const VERSION = '1.0.0';

    public static function create(): SymfonyApplication
    {
        $parser = new PhpParser();
        $registry = RuleRegistry::withDefaultRules();
        $fileScanner = new FileScanner($parser);
        $scanner = new Scanner($fileScanner, $registry);
        $scanner->setVersion(self::VERSION);

        $report = new Report();
        $configLoader = new ConfigurationLoader();

        $application = new SymfonyApplication('PHP Sentinel', self::VERSION);
        $application->add(new ScanCommand($scanner, $report, $configLoader));
        $application->setDefaultCommand('scan', false);

        return $application;
    }
}
