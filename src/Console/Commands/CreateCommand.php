<?php

namespace Wisdech\LetsEncrypt\Console\Commands;

use Illuminate\Console\Command;
use Wisdech\LetsEncrypt\Facade\LetsEncrypt;

class CreateCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'wisdech:letsencrypt {--domain=} {--action=}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '使用 Let\'s Encrypt 生成 SSL 证书';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        $action = $this->option('action') ?: $this->choice('选择要执行的操作', ['创建证书订单', '验证域名所有权', '生成SSL证书']);

        $result = match ($action) {
            '创建证书订单' => LetsEncrypt::createOrder(
                $this->option('domain') ?: $this->ask('请输入域名')
            ),
            '验证域名所有权' => LetsEncrypt::verifyOrder(
                $this->option('domain') ?: $this->ask('请输入域名')
            ),
            '生成SSL证书' => LetsEncrypt::finishOrder(
                $this->option('domain') ?: $this->ask('请输入域名')
            ),
        };

        if (is_array($result) && key_exists('dns', $result)) {
            $this->info('请添加以下DNS记录：');
            $this->table(
                ['解析类型', '主机记录', '解析记录'],
                [
                    [$result['dns']['type'], $result['dns']['name'], $result['dns']['record']]
                ]
            );
        }

        if (is_array($result) && key_exists('sslPrivateKey', $result)) {
            $this->info('证书生成成功');
            $this->info('私钥位置：' . $result['sslPrivateKey']);
            $this->info('证书位置：' . $result['sslCertificate']);
            $this->info('发行者证书位置：' . $result['sslIssuerCertificate']);
        }

        if (is_bool($result)) {
            $result
                ? $this->info('DNS验证成功')
                : $this->warn('DNS验证失败');
        }
    }
}
