<?php

declare(strict_types=1);

$input = $_POST['args'];
$output = shell_exec('dir ' . $input);
echo $output;
