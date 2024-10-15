<?php

return [
    /** 申请证书使用的邮箱 */
    'email' => env('LETS_ENCRYPT_EMAIL', 'info@wisdech.com'),

    /** 是否使用测试环境 */
    'use_staging' => env('LETS_ENCRYPT_TEST', false),
];