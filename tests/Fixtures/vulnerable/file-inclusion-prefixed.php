<?php

declare(strict_types=1);

$page = $_REQUEST['p'];
$path = __DIR__ . '/pages/' . $page;
include $path;
