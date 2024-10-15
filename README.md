# Let's Encrypt 证书申请 Laravel 实现 (Acme)

## 安装使用

```bash
#添加依赖
composer require wisdech/laravel-encrypt
```

## Laravel项目中

```bash
#发布配置文件
php artisan vendor:publish --tag=lets-encrypt-config
```

```dotenv
#在.env文件填写配置信息
LETS_ENCRYPT_EMAIL=
```

```php
//使用Facade
use Wisdech\LetsEncrypt\Facade\LetsEncrypt

LetsEncrypt::createOrder('domain')
```

## 不使用Facade
```php
$le=new Wisdech\LetsEncrypt\LetsEncrypt('email')

$le->createOrder('domain')
```