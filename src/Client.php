<?php
/**
 * Created by PhpStorm.
 * User: 85210755@qq.com
 * NickName: 柏宇娜
 * Date: 2018/10/29 14:54
 */

namespace Tl;

Class Client
{
    private static $METHOD_POST = "POST";
    private static $BUFFER_SIZE = 1024;

    public static $SSO_SERVICE = "SSOService";
    public static $STATUS_OK = "OK";
    public static $STATUS_ERR = "error";
    public static $ERR_MESSAGE = "message";
    public static $ERR_CODE = "errorCode";
    public static $RETURN_VALUE = "returnValue";

    private $serverAddress = "";
    private $serverUrl = "";
    private $ssoid = "ime_public_ssoid";
    private $_sysid = "";
    private $version = "1.0";
    private $_signMethod = "MD5";
    private $privateKey;
    private $publicKey;
    private $timeStr = null;

    public function getServerAddress()
    {
        return $this->serverAddress;
    }

    public function setServerAddress($serverAddress)
    {
        $this->serverAddress = $serverAddress;
        $this->serverUrl     = $serverAddress;
    }

    public function getSignMethod()
    {
        return $this->_signMethod;
    }

    public function setSignMethod($signMethod)
    {
        $this->_signMethod = $signMethod;
    }

    //验签
    function loadPublicKey($alias, $path, $pwd)
    {
        echo $path . '---' . $pwd;
        $priKey = file_get_contents($path);
        $res    = openssl_get_privatekey($priKey);
        print_r($res);

        ($res) or die('您使用的私钥格式错误，请检查私钥配置');

        openssl_sign("errorCode=SOA.NoSuchMethod&errorMessage=找不到相应的服务:aaa.createMember", $sign, $res);

        openssl_free_key($res);

        $sign = base64_encode($sign);

        echo '<br>' . $sign . '<br>';

        //调用openssl内置方法验签，返回bool值
        return $res;
    }

    public function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
    }

    public function setPublicKey($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function getSysId()
    {
        return $this->_sysid;
    }

    public function setSysId($sysid)
    {
        $this->_sysid = $sysid;
    }

    public function getVersion()
    {
        return $this->version;
    }

    public function setVersion($version)
    {
        $this->version = $version;
    }

    public function getTimeStr()
    {
        return $this->timeStr;
    }

    public function setTimeStr($timeStr)
    {
        $this->timeStr = $timeStr;
    }

    public function request($service, $method, $param, $url = '')
    {
        $pageAPI = ['setPayPwd', 'updatePayPwd', 'resetPayPwd'];

        $request["service"] = $service;
        $request["method"]  = $method;
        $request["param"]   = $param;

        $strRequest = json_encode($request, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        //$strRequest = str_replace("\r\n", "", $strRequest);

        $req['sysid'] = $this->_sysid;
        if ($this->privateKey != null && "" != $this->_sysid) {
            $timestamp        = date("Y-m-d H:i:s", time());
            $sign             = $this->sign($this->_sysid, $strRequest, $timestamp);
            $req['sign']      = $sign;
            $req['timestamp'] = $timestamp;
            $req['v']         = $this->version;
        }
        $req['req'] = $strRequest;

        //页面请求方式，需兼容JAVA对参数值urlencode两次
        if (in_array($method, $pageAPI)) {
            $req_str = '';
            foreach ($req as $k => $v) {
                $req_str .= $k . '=' . urlencode(urlencode($v)) . '&';
            }
            return $url . '?' . trim($req_str, '&');
        }
//dump($req);die;
        $result = $this->request2($req);
        return $this->checkResult($result);
    }

    private function request2($args)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->serverUrl);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($args));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_AUTOREFERER, 0);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }

    private function checkResult($result)
    {
        $arr         = json_decode($result, true);
        $sign        = $arr['sign'];
        $signedValue = $arr['signedValue'];
        if ($sign != null) {
            if (RSAUtil::verify($this->publicKey, $signedValue, $sign)) {
                unset($arr['sign']);
                $arr['signedValue'] = json_decode($signedValue, true);
                return $arr;
            }
        }
        throw new \Exception("签名验证错误");
    }

    private function sign($sysid, $req, $timestamp)
    {
        if ("SHA1WithRSA" == $this->_signMethod) {
            return RSAUtil::sign($this->privateKey, $sysid . $req . $timestamp);
        } else {
            throw new \Exception("签名算法仅支持SHA1WithRSA");
        }
    }
}