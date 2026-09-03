<?php

declare(strict_types=1);

$pdo = new PDO('sqlite::memory:');
$query = 'SELECT * FROM users WHERE id = 1';
$pdo->query($query);
