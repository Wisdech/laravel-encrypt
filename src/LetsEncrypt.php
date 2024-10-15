<?php

namespace Wisdech\LetsEncrypt;

use AcmePhp\Core\AcmeClient;
use AcmePhp\Core\Challenge\Dns\DnsDataExtractor;
use AcmePhp\Core\Http\Base64SafeEncoder;
use AcmePhp\Core\Http\SecureHttpClientFactory;
use AcmePhp\Core\Http\ServerErrorHandler;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use AcmePhp\Ssl\CertificateRequest;
use AcmePhp\Ssl\DistinguishedName;
use AcmePhp\Ssl\Generator\KeyPairGenerator;
use AcmePhp\Ssl\KeyPair;
use AcmePhp\Ssl\Parser\KeyParser;
use AcmePhp\Ssl\PrivateKey;
use AcmePhp\Ssl\PublicKey;
use AcmePhp\Ssl\Signer\DataSigner;
use GuzzleHttp\Client as GuzzleHttpClient;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;

class LetsEncrypt
{
    private string $email;
    private string $userPublicKeyPath;
    private string $userPrivateKeyPath;
    private string $domainPrivateKeyPath;
    private string $domainCertificatePath;
    private string $issuerCertificatePath;
    private KeyPair $keyPair;
    private AcmeClient $acmeClient;
    private DnsDataExtractor $dnsDataExtractor;

    const LE_PROD_ENDPOINT = 'https://acme-v02.api.letsencrypt.org/directory';
    const LE_TEST_ENDPOINT = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    /**
     * 使用 LetsEncrypt
     * @param string $email 申请邮箱
     * @param bool $test 是否使用测试环境
     */
    public function __construct(string $email, bool $test = false)
    {
        $this->setupAccountPath($email);

        $this->email = $email;
        $this->keyPair = $this->setAccountKeyPair();
        $this->acmeClient = $this->setAcmeClient($test);
        $this->dnsDataExtractor = new DnsDataExtractor();
    }

    /**
     * 创建证书请求
     * @param string $domain 域名
     * @return array[] 需要添加的DNS解析记录
     */
    public function createOrder(string $domain): array
    {
        $this->acmeClient->registerAccount($this->email);
        $challenge = $this->acmeClient->requestAuthorization($domain)[0];

        $challengeCacheKey = $this->replaceSpecialCharacters($domain);
        Cache::put($challengeCacheKey, $challenge->toArray());

        return [
            'dns' => [
                'type' => 'txt',
                'name' => $this->dnsDataExtractor->getRecordName($challenge),
                'record' => $this->dnsDataExtractor->getRecordValue($challenge),
            ],
        ];
    }

    /**
     * 域名所有权验证 (校验DNS)
     * @param string $domain 域名
     * @return bool 校验结果
     */
    public function verifyOrder(string $domain): bool
    {
        $challengeCacheKey = $this->replaceSpecialCharacters($domain);
        $challenge = Cache::get($challengeCacheKey);
        $challenge = AuthorizationChallenge::fromArray($challenge);
        $challengeDNSName = $this->dnsDataExtractor->getRecordName($challenge);
        $challengeDNSValue = $this->dnsDataExtractor->getRecordValue($challenge);

        $dns = dns_get_record($challengeDNSName, DNS_TXT);
        if ($dns && key_exists('txt', $dns[0])) {
            return $dns[0]['txt'] === $challengeDNSValue;
        }
        return false;
    }

    /**
     * 完成申请，获取证书
     * @param string $domain 域名
     * @return array 证书存储路径
     */
    public function finishOrder(string $domain): array
    {
        $challengeCacheKey = $this->replaceSpecialCharacters($domain);
        $challenge = Cache::get($challengeCacheKey);

        $this->acmeClient->challengeAuthorization(
            AuthorizationChallenge::fromArray($challenge)
        );

        $dn = new DistinguishedName($domain);

        $keyPairGenerator = new KeyPairGenerator();

        $domainKeyPair = $keyPairGenerator->generateKeyPair();

        $this->setupCertificatePath($domain);

        file_put_contents($this->domainPrivateKeyPath, $domainKeyPair->getPrivateKey()->getPEM());

        $csr = new CertificateRequest($dn, $domainKeyPair);

        $certificateResponse = $this->acmeClient->requestCertificate($domain, $csr);

        file_put_contents($this->domainCertificatePath, $certificateResponse->getCertificate()->getPEM());
        file_put_contents($this->issuerCertificatePath, $certificateResponse->getCertificate()->getIssuerCertificate()->getPEM());

        Cache::forget($challengeCacheKey);

        return [
            'sslPrivateKey' => $this->domainPrivateKeyPath,
            'sslCertificate' => $this->domainCertificatePath,
            'sslIssuerCertificate' => $this->issuerCertificatePath,
        ];
    }

    private function setAcmeClient(bool $test = false): AcmeClient
    {
        $secureHttpClientFactory = new SecureHttpClientFactory(
            new GuzzleHttpClient(),
            new Base64SafeEncoder(),
            new KeyParser(),
            new DataSigner(),
            new ServerErrorHandler()
        );

        $secureHttpClient = $secureHttpClientFactory->createSecureHttpClient($this->keyPair);

        return new AcmeClient($secureHttpClient,
            $test ? self::LE_TEST_ENDPOINT : self::LE_PROD_ENDPOINT,
        );
    }

    private function setAccountKeyPair(): KeyPair
    {

        if (!file_exists($this->userPrivateKeyPath)) {
            $keyPairGenerator = new KeyPairGenerator();
            $keyPair = $keyPairGenerator->generateKeyPair();

            file_put_contents($this->userPublicKeyPath, $keyPair->getPublicKey()->getPEM());
            file_put_contents($this->userPrivateKeyPath, $keyPair->getPrivateKey()->getPEM());
        } else {
            $publicKey = new PublicKey(file_get_contents($this->userPublicKeyPath));
            $privateKey = new PrivateKey(file_get_contents($this->userPrivateKeyPath));

            $keyPair = new KeyPair($publicKey, $privateKey);
        }

        return $keyPair;
    }

    private function replaceSpecialCharacters(string $string, bool $wildcard = false): string
    {
        return preg_replace('/[^a-zA-Z0-9]+/', '_',
            $wildcard ? str_replace('*', '_wildcard', $string) : $string
        );
    }

    private function setupAccountPath(string $email): void
    {
        $email = $this->replaceSpecialCharacters($email);

        if (!file_exists(storage_path('cert'))) {
            mkdir(storage_path('cert'));
        }

        if (!file_exists(storage_path('cert/account'))) {
            mkdir(storage_path('cert/account'));
        }

        $this->userPublicKeyPath = storage_path("cert/account/$email.public.pem");
        $this->userPrivateKeyPath = storage_path("cert/account/$email.private.pem");
    }

    private function setupCertificatePath(string $domain): void
    {
        $domain = $this->replaceSpecialCharacters($domain, wildcard: true);

        if (!file_exists(storage_path('cert'))) {
            mkdir(storage_path('cert'));
        }

        if (!file_exists(storage_path('cert/certificate'))) {
            mkdir(storage_path('cert/certificate'));
        }

        if (!file_exists(storage_path("cert/certificate/$domain"))) {
            mkdir(storage_path("cert/certificate/$domain"));
        }

        $time = Carbon::now()->timestamp;

        $this->domainPrivateKeyPath = storage_path("cert/certificate/$domain/{$time}_$domain.key");
        $this->domainCertificatePath = storage_path("cert/certificate/$domain/{$time}_$domain.pem");
        $this->issuerCertificatePath = storage_path("cert/certificate/$domain/{$time}_lets_encrypt.pem");
    }

}
