<?php

return [
    'header_path' => base_path('storage/ffi/oqs.h'),
    'library_path' => env('LIBOQS_SO_PATH', '/usr/local/lib/liboqs.so'),
];
