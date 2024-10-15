<?php

namespace Wisdech\LetsEncrypt;

use Illuminate\Support\ServiceProvider;
use Wisdech\LetsEncrypt\Console\Commands\CreateCommand;

class LetsEncryptProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->app->singleton(LetsEncrypt::class, function ($app) {
            return new LetsEncrypt(
                config('letsencrypt.email'),
                config('letsencrypt.use_staging'),
            );
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([CreateCommand::class]);
        }

        $this->publishes([
            __DIR__ . '/../config/letsencrypt.php' => config_path('letsencrypt.php'),
        ], 'lets-encrypt-config');
    }
}
