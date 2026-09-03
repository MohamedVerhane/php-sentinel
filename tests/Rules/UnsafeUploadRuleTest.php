<?php

declare(strict_types=1);

namespace PhpSentinel\Tests\Rules;

use PhpSentinel\Support\Severity;
use PhpSentinel\Tests\TestCase;

final class UnsafeUploadRuleTest extends TestCase
{
    public function testDetectsMoveUploadedFileWithoutValidation(): void
    {
        $code = <<<'PHP'
            <?php
            $tmp = $_FILES['avatar']['tmp_name'];
            $dest = '/var/www/uploads/avatar.png';
            move_uploaded_file($tmp, $dest);
            PHP;

        $finding = $this->assertSingleFinding($this->analyzeWithRule($code, 'SEC005'), 'SEC005');
        self::assertSame(Severity::MEDIUM, $finding->severity);
        self::assertSame('CWE-434', $finding->cwe);
    }

    public function testDetectsDestinationFromFilesName(): void
    {
        $code = <<<'PHP'
            <?php
            $destination = '/var/www/uploads/' . $_FILES['avatar']['name'];
            move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
            PHP;

        $findings = $this->analyzeWithRule($code, 'SEC005');
        self::assertNotEmpty($findings);

        $titles = array_map(static fn ($finding) => $finding->title, $findings);
        self::assertContains('Unsafe Upload Destination', $titles);
    }

    public function testIgnoresValidatedUpload(): void
    {
        $code = <<<'PHP'
            <?php
            $mime = finfo_file(finfo_open(FILEINFO_MIME_TYPE), $_FILES['pdf']['tmp_name']);
            if (in_array($mime, ['application/pdf'], true)) {
                move_uploaded_file($_FILES['pdf']['tmp_name'], '/uploads/file.pdf');
            }
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC005'));
    }

    public function testIgnoresExplicitExtensionCheck(): void
    {
        $code = <<<'PHP'
            <?php
            $ext = pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION);
            if (!in_array($ext, ['png', 'jpg', 'gif'], true)) {
                exit('Bad extension');
            }
            move_uploaded_file($_FILES['f']['tmp_name'], '/uploads/x.' . $ext);
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC005'));
    }
}
