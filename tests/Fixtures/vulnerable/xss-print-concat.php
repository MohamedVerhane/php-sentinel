<?php

declare(strict_types=1);

print $_POST['message'];

$template = 'Hello ' . $_GET['user'];
echo $template;
