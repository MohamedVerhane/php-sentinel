<?php

declare(strict_types=1);

$mysqli = new mysqli();
$loggedIn = $_POST['user'];
$query = 'SELECT * FROM accounts WHERE name = "' . $loggedIn . '"';
$mysqli->multi_query($query);
