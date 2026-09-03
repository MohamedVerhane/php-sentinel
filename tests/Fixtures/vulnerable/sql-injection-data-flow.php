<?php

declare(strict_types=1);

$pdo = new PDO('sqlite::memory:');
$id = $_GET['id'];
$userId = $id;
$final = strtoupper($userId);
$stmt = $pdo->query('SELECT * FROM users WHERE id = ' . $final);
