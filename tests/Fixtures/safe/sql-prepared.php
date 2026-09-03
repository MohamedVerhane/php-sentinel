<?php

declare(strict_types=1);

$pdo = new PDO('sqlite::memory:');
$id = $_GET['id'];
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $id]);
