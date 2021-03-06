<?php

/**
 * Created by PhpStorm.
 * User: 85210755@qq.com
 * NickName: 柏宇娜
 * Date: 2018/10/29 15:31
 */

namespace Tl;

use Tl\Client;
use Tl\RSAUtil;

class Access
{
    /**
     * sysid = "100009000309"
     * serverAddress = "https://yun.allinpay.com/service/soa";
     * pwd = "013764"
     * alias = "100009000309";
     * signMethod = "SHA1WithRSA"
     */
    private $client;
    private $rsaunit;
    private $alias;
    private $pwd;
    private $publicKey;
    private $privateKey;
    private $config = [
        'serverAddress' => '',
        'sysId'         => '',
        'alias'         => '',
        'privatePath'   => '',
        'publicPath'    => '',
        'privateKey'    => '',
        'publicKey'     => '',
        'pwd'           => '',
        'signMethod'    => '',
    ];

    public function __construct(array $config = [])
    {
        if (!$config)
            $config = include('config.php');
        $this->config     = array_merge($this->config, $config);
        $this->privateKey = $this->config['privateKey'] = RSAUtil::loadPrivateKey($this->config['alias'], __DIR__ . DIRECTORY_SEPARATOR . $this->config['privatePath'], $this->config['pwd']);
        $this->publicKey  = $this->config['publicKey'] = RSAUtil::loadPublicKey($this->config['alias'], __DIR__ . DIRECTORY_SEPARATOR . $this->config['publicPath'], $this->config['pwd']);
        $this->alias      = $this->config['alias'];
        $this->pwd        = $this->config['pwd'];
        unset($this->config['privatePath'], $this->config['publicPath'], $this->config['alias'], $this->config['pwd']);
        $this->client  = new Client();
        $this->rsaunit = new RSAUtil($this->publicKey, $this->privateKey);
        foreach ($this->config as $key => $value) {
            $method = 'set' . ucfirst($key);
            $this->client->$method($value);
        }
    }

    /**
     * @return mixed
     */
    public function lunch()
    {
        $args = func_get_args();
        try {
            $service      = $args[0];
            $method       = $args[1];
            $param        = [];
            $type_except  = ['bizUserId', 'phone', 'verificationCode', 'bankCardNo', 'accountSetNo', 'bizOrderNo', 'payerId'];
            $need_encrypt = ['identityNo', 'cardNo'];
            foreach ($args[2] as $key => $value) {
                if (in_array($key, $type_except))
                    $value = (string)$value;
                if (in_array($key, $need_encrypt))
                    $value = $this->rsaunit->encrypt((string)$value);
                $param[$key] = $value;
            }

            $result = $this->client->request($service, $method, $param, $args[3] ?? '');
            return $result;
        } catch (\Exception $e) {
            return $e->getMessage();
        }
    }

    public function encrypt($content)
    {
        return $this->rsaunit->encrypt((string)$content);
    }

    public function decrypt($content)
    {
        return $this->rsaunit->decrypt($content);
    }

    public function check($str, $sign)
    {
        return RSAUtil::verify($this->publicKey, $str, $sign);
    }
}