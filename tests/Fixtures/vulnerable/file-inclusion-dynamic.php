<?php

declare(strict_types=1);

$module = $_GET['module'];
require_once 'modules/' . $module . '.php';
