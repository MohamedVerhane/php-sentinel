<?php

declare(strict_types=1);

if (isset($_FILES['upload'])) {
    $tmpName = $_FILES['upload']['tmp_name'];
    $destination = '/var/www/uploads/' . $_FILES['upload']['name'];
    move_uploaded_file($tmpName, $destination);
}
