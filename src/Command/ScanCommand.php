<?php

declare(strict_types=1);

namespace PhpSentinel\Command;

use PhpSentinel\Config\Configuration;
use PhpSentinel\Config\ConfigurationLoader;
use PhpSentinel\Exception\ConfigurationException;
use PhpSentinel\Exception\InvalidInputException;
use PhpSentinel\Report\Report;
use PhpSentinel\Scanner\Scanner;
use PhpSentinel\Support\Severity;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The `scan` command: discovers, parses and analyses PHP files, then renders a
 * report.
 *
 * Exit codes:
 *   0  no findings
 *   1  findings detected
 *   2  invalid input / configuration / runtime error
 */
final class ScanCommand extends Command
{
    public function __construct(
        private readonly Scanner $scanner,
        private readonly Report $report,
        private readonly ConfigurationLoader $configLoader,
    ) {
        parent::__construct('scan');
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Scans PHP source code for security vulnerabilities.')
            ->setHelp(
                "Discovers PHP files in the given paths, parses each into an AST, runs the enabled security rules\n"
                . "and renders a report.\n\n"
                . "Examples:\n"
                . "  sentinel scan .\n"
                . "  sentinel scan src/ tests/\n"
                . "  sentinel scan . --format=json --severity=high\n"
                . "  sentinel scan . --ignore=vendor --ignore=cache\n"
                . "  sentinel scan . --config=.php-sentinel.php\n"
            )
            ->addArgument(
                'paths',
                InputArgument::IS_ARRAY | InputArgument::OPTIONAL,
                'One or more files or directories to scan.',
                ['.'],
            )
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: console or json.')
            ->addOption('severity', null, InputOption::VALUE_REQUIRED, 'Minimum severity to report: INFO, LOW, MEDIUM, HIGH or CRITICAL.')
            ->addOption('config', null, InputOption::VALUE_REQUIRED, 'Path to a .php-sentinel.php configuration file.')
            ->addOption('ignore', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Additional paths to ignore (may be repeated).')
            ->addOption('no-progress', null, InputOption::VALUE_NONE, 'Disable the progress indicator.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $paths = $this->paths($input);
            $this->assertPathsExist($paths);
            $config = $this->resolveConfiguration($input, $output, $paths);
            $report = $this->runScan($config, $input, $output);

            return $report->hasFindings() ? 1 : 0;
        } catch (InvalidInputException | ConfigurationException $e) {
            $output->writeln(sprintf('<error>PHP Sentinel: %s</error>', $e->getMessage()));

            return 2;
        }
    }

    /**
     * @param list<string> $paths
     */
    private function assertPathsExist(array $paths): void
    {
        foreach ($paths as $path) {
            if (!file_exists($path) && !is_dir($path)) {
                throw new InvalidInputException(sprintf('The path "%s" does not exist.', $path));
            }
        }
    }

    /**
     * @return list<string>
     */
    private function paths(InputInterface $input): array
    {
        $paths = (array) $input->getArgument('paths');

        return array_values(array_filter(array_map('trim', $paths), static fn (string $p): bool => $p !== ''));
    }

    /**
     * @param list<string> $paths
     */
    private function resolveConfiguration(InputInterface $input, OutputInterface $output, array $paths): Configuration
    {
        $config = Configuration::defaults($paths);

        $configOption = $input->getOption('config');
        $overrides = is_string($configOption) && $configOption !== ''
            ? $this->configLoader->load($configOption)
            : $this->configLoader->loadFromDirectory(getcwd() !== false ? getcwd() : '.');

        if ($overrides !== null) {
            $config = $config->with($overrides);
        }

        $format = $input->getOption('format');
        if (is_string($format) && $format !== '') {
            if (!$this->report->supports($format)) {
                throw new InvalidInputException(sprintf(
                    'Unknown output format "%s". Supported formats: %s.',
                    $format,
                    implode(', ', $this->report->formats()),
                ));
            }
            $config = $config->with(['outputFormat' => $format]);
        }

        $severity = $input->getOption('severity');
        if (is_string($severity) && $severity !== '') {
            $config = $config->with(['severityThreshold' => Severity::fromName($severity)]);
        }

        $ignored = (array) $input->getOption('ignore');
        if ($ignored !== []) {
            $config = $config->with([
                'ignoredPaths' => array_values(array_unique(array_merge($config->ignoredPaths, $ignored))),
            ]);
        }

        if ((bool) $input->getOption('no-progress')) {
            $config = $config->with(['showProgress' => false]);
        }

        if ($output->isVerbose()) {
            $config = $config->with(['verbose' => true]);
        }

        return $config;
    }

    private function runScan(Configuration $config, InputInterface $input, OutputInterface $output): \PhpSentinel\Scanner\ScanResult
    {
        $showProgress = $config->showProgress && $config->outputFormat === 'console';

        $result = $this->scanner->scan(
            $config,
            $showProgress ? $this->progress($output) : null,
        );

        if ($showProgress) {
            $output->writeln('');
        }

        $rendered = $this->report->render($result, $config->outputFormat);
        $output->write($rendered);

        return $result;
    }

    /**
     * @return callable(int, int): void
     */
    private function progress(OutputInterface $output): callable
    {
        return static function (int $done, int $total) use ($output): void {
            $output->write(sprintf("\r  Scanning %d/%d ...", $done, $total));
        };
    }
}
