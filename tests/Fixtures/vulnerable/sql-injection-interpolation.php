<?php

declare(strict_types=1);

$pdo = new PDO('sqlite::memory:');
$id = $_GET['id'];
$pdo->query("SELECT * FROM users WHERE id = $id");
