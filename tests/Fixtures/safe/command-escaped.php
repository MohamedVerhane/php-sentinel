<?php

declare(strict_types=1);

$user = $_POST['args'];
$command = escapeshellarg($user);
system('echo ' . $command);
