<?php

declare(strict_types=1);

if ($_FILES['file']['error'] === UPLOAD_ERR_OK) {
    $allowed = ['image/png', 'image/jpeg'];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        exit('Finfo unavailable');
    }
    $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);

    if (in_array($mime, $allowed, true)) {
        $extension = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
        $target = '/var/www/uploads/' . uniqid('', true) . '.' . $extension;
        move_uploaded_file($_FILES['file']['tmp_name'], $target);
    }
}
