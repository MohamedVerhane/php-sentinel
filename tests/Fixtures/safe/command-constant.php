<?php

declare(strict_types=1);

system('backup --full');
exec('git status');
