<?php

declare(strict_types=1);

$connection = new mysqli();
$name = $_POST['name'];
$statement = 'SELECT * FROM users WHERE username = ' . $name;
mysqli_query($connection, $statement);
