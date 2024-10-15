<?php

namespace Wisdech\LetsEncrypt\Facade;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array createOrder(string $domain)
 * @method static bool verifyOrder(string $domain)
 * @method static array finishOrder(string $domain)
 */
class LetsEncrypt extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Wisdech\LetsEncrypt\LetsEncrypt::class;
    }
}