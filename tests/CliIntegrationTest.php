<?php

declare(strict_types=1);

namespace PhpSentinel\Tests;

use PhpSentinel\Application;

final class CliIntegrationTest extends TestCase
{
    /**
     * @param list<string> $args
     *
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runCli(array $args): array
    {
        $bin = (string) realpath(__DIR__ . '/../bin/sentinel');
        $command = array_merge([PHP_BINARY, $bin], $args);

        $process = proc_open(
            $command,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            dirname(__DIR__),
        );

        self::assertIsResource($process);

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);

        return ['code' => $code, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
    }

    public function testVersionExitsZero(): void
    {
        $result = $this->runCli(['--version']);

        self::assertSame(0, $result['code']);
        self::assertStringContainsString('PHP Sentinel', $result['stdout']);
        self::assertStringContainsString(Application::VERSION, $result['stdout']);
    }

    public function testVulnerableScanExitsOne(): void
    {
        $result = $this->runCli(['scan', $this->fixture('vulnerable'), '--no-progress']);

        self::assertSame(1, $result['code']);
        self::assertStringContainsString('SEC001', $result['stdout']);
    }

    public function testSafeScanExitsZero(): void
    {
        $result = $this->runCli(['scan', $this->fixture('safe'), '--no-progress']);

        self::assertSame(0, $result['code']);
        self::assertStringContainsString('No findings', $result['stdout']);
    }

    public function testNonexistentPathExitsTwo(): void
    {
        $result = $this->runCli(['scan', 'does-not-exist', '--no-progress']);

        self::assertSame(2, $result['code']);
    }

    public function testInvalidFormatExitsTwo(): void
    {
        $result = $this->runCli(['scan', $this->fixture('safe'), '--format=bogus', '--no-progress']);

        self::assertSame(2, $result['code']);
    }

    public function testUnknownSeverityExitsTwo(): void
    {
        $result = $this->runCli(['scan', $this->fixture('safe'), '--severity=NOT_A_LEVEL', '--no-progress']);

        self::assertSame(2, $result['code']);
    }

    public function testJsonOutputIsValid(): void
    {
        $result = $this->runCli(['scan', $this->fixture('vulnerable'), '--format=json', '--no-progress']);

        self::assertSame(1, $result['code']);

        $data = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);

        self::assertSame(Application::VERSION, $data['version']);
        self::assertStringEndsWith('vulnerable', $data['paths'][0]);
        self::assertArrayHasKey('summary', $data);
        self::assertArrayHasKey('findings', $data);
        self::assertNotEmpty($data['findings']);

        $first = $data['findings'][0];
        self::assertArrayHasKey('rule_id', $first);
        self::assertArrayHasKey('severity', $first);
        self::assertArrayHasKey('file', $first);
        self::assertArrayHasKey('line', $first);
    }

    public function testJsonOutputForSafeScanIsValid(): void
    {
        $result = $this->runCli(['scan', $this->fixture('safe'), '--format=json', '--no-progress']);

        self::assertSame(0, $result['code']);

        $data = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);

        self::assertSame([], $data['findings']);

        $summary = $data['summary'];
        self::assertSame(0, $summary['high'] + $summary['medium'] + $summary['low']);
    }
}
