<?php
namespace sh39\AWSLib ;

// AWS SDK V3 必須

use Aws\CloudFront\CloudFrontClient as cloudfront;

/*
必須変数
$expire : cookieの有効期限（設定しない場合、15分）
$resourceKey : 証明書を有効にするファイル or ディレクトリ
$domain : 証明書を有効にするドメイン（ルートドメインの場合、最初に.をつける）
$privateKey : SSHプライベートキーの絶対パス
$keyPairId : A******************QのIP名

その他
$remoteAddress : 現在閲覧しているIPアドレス
*/

class setSignedCookie extends cloudfront
{
	private $resourceKey ;
	private $remoteAddress ;
	private $domain ;
	private $privateKey ;
	private $keyPairId ;

	function __construct(array $args){
		$this->expire        = ( !empty( $args['expire'] ))
							 ? $args['expire']
							 : time()+60*15 ;
		$this->resourceKey   = $args['resourceKey'] ;
		$this->remoteAddress = $_SERVER['REMOTE_ADDR'] ;
		$this->domain        = $args['domain'] ;
		$this->privateKey    = $args['privateKey'] ;
		$this->keyPairId     = $args['keyPairId'] ;
	}
	function customPolicy(){
		return <<<POLICY
		{
		    "Statement": [
		        {
		            "Resource": "{$this->resourceKey}",
		            "Condition": {
		                "IpAddress": {"AWS:SourceIp": "{$this->remoteAddress}/32"},
		                "DateLessThan": {"AWS:EpochTime": {$this->expires}}
		            }
		        }
		    ]
		}
		POLICY;
	}
	function signedCookie(){
		return $cloudFront->getSignedCookie([
			"policy" => $this->customPolicy(),
			"private_key" => $this->privateKey,
			"key_pair_id" => $this->keyPairId
		]);
	}
	function set(){
		foreach ($this->signedCookie() as $name => $value) {
			setcookie($name, $value, 0, "", $this->domain, true, true);
		}
	}
}