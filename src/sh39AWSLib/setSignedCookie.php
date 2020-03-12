<?php

namespace sh39\AWSLib ;

class setSignedCookie
{
	private $expire ;
	private $resourceKey ;
	private $remoteAddress ;
	private $signedCookie ;
	private $domain ;
	private $privateKey ;
	private $keyPairId ;

	function __construct(array $args){
		$this->expire        = $args['expire'] ;
		$this->resourceKey   = $args['resourceKey'] ;
		$this->remoteAddress = $_SERVER['REMOTE_ADDR'] ;
		$this->signedCookie  = $args['signedCookie'] ;
		$this->domain        = ".".$args['domain'] ;
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
		$signedCookieCustomPolicy = $cloudFront->getSignedCookie([
			"policy" => customPolicy(),
			"private_key" => $this->privateKey,
			"key_pair_id" => $this->keyPairId
		]);
	}
	function set(){
		foreach ($this->signedCookie as $name => $value) {
			setcookie($name, $value, 0, "", $this->domain, true, true);
		}
	}
}