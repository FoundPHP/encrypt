<?php
/*	(C)2005-2021 FoundPHP Development framework.
*	   name: AES DES Encrypt
*	 weburl: http://www.FoundPHP.com
* 	   mail: master@FoundPHP.com
*	 author: 孟大川
*	version: 1.02
*	  start: 2013-05-24
*	 update: 2020-02-25
*	payment: 免费
*	This is not a freeware,use is subject to license terms.
*	此软件为授权使用软件，请参考软件协议。
*	http://www.foundphp.com/?m=agreement
Relation:
encrypt.php

Example:
	FoundPHP AES/DES加/解密方法
	type	AES与DES
	key		加密密钥AES为16位，DES为8位
	iv		加密偏移值AES为16位，DES为8位
	
	$config['encrypt']['type'] 		= 'AES';						//AES与DES
	$config['encrypt']['key'] 		= '66054b8866054b8866054b8866054b88';			//对接密钥,AES为32位，DES为8位
	$config['encrypt']['iv'] 		= 'www.FoundPHP.comwww.FoundPHP.com';			//加密偏移值AES为32位，DES为8位
	
	$GLOBALS['FoundPHP_encrypt']	= new FoundPHP_encrypt($config['encrypt']);
	echo $str	= $GLOBALS['FoundPHP_encrypt']->encode('test code');
	echo $GLOBALS['FoundPHP_encrypt']->decode($str);
*/
class FoundPHP_encrypt{
	var $type	= 'aes';
	var $code	= '';
	var $raw	= '';
	var $ver	= '1.21.130';
	var $key	= 'www.FoundPHP.com';
	var $iv		= 'www.FoundPHP.com';
	var $lang	= array(
		'des_leng'		=> '抱歉，DES加密key长度为8',
		'aes_leng'		=> '抱歉，AES加密key长度为32位',
		'error_info'	=> 'FoundPHP 请打开 php.ini 开启 openssl 模块',
		
	);
	function __construct($set=array()){
		$this->type		= $set['type']!=''?strtolower($set['type']):$this->type;
		if (in_array($this->type,array('aes','des'))){
			$this->key	= trim($set['key'])!=''?trim($set['key']):$this->iv;
			$this->iv	= trim($set['iv'])!=''?trim($set['iv']):$this->iv;
			switch($this->type){
				case'des':
					if (strlen($this->key)!=8){
						$error  = $this->lang['des_leng'];
						function_exists('foundphp_error')?foundphp_error($error):die($error);
					}
					//未设置偏移值则采用key
					if (strlen(trim($set['iv']))!=8){
						$this->iv	= $this->key;
					}else{
						$this->iv	= trim($set['iv']);
					}
					$this->raw	= 1;
				break;
				default:
					if (strlen($this->key)!=32){
						$error  = $this->lang['aes_leng'];
						function_exists('foundphp_error')?foundphp_error($error):die($error);
					}
					$this->raw	= true;
					//未设置偏移值则采用key
					if (strlen(trim($set['iv']))!=16){
						$this->iv	= $this->key;
					}else{
						$this->iv	= trim($set['iv']);
					}
				break;
			}
		}
	}
	
	//加密
	function encrypt($str,$type='base64'){return $this->encode($str,$type);}
	function encode($str,$type='base64'){
		//php7 采用openssl
		if (floatval(PHP_VERSION)>5.6){
			if (!function_exists('openssl_encrypt')){
				$str 	= $this->foundphp_encrypt($str,$this->key);
			}else{
				$str	= base64_encode(openssl_encrypt($str,'AES-256-CBC',substr($this->key,0,32),OPENSSL_RAW_DATA,substr($this->iv, 0, 16)));
		}
		}else{
			if ($this->type=='aes'){
				$module		= mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
				mcrypt_generic_init($module, $this->key, $this->iv);
				$str		= base64_encode(mcrypt_generic($module, $str));
			}else{
				$blocksize	= mcrypt_get_block_size(MCRYPT_DES,MCRYPT_MODE_CBC);
				$pad		= $blocksize-(strlen($str)%$blocksize);
				$str		= $str.str_repeat(chr($pad),$pad);
				$str		= base64_encode(mcrypt_cbc(MCRYPT_DES,$this->key,$str,MCRYPT_ENCRYPT,$this->iv));
			}
		}
		
		if($type!='base64'){$str = str_replace(array('+','/','='),array('0o0','0_0','-_-'),$str);}
		return $str;
	}
	function foundphp_encrypt($data, $key){
		$k		= substr(md5($key),10,-10);
		$x		= 0;
		$len	= strlen($data);
		$l		= strlen($k);
		$ch=$str= '';
		for ($i=0; $i<$len;$i++){
			if ($x == $l){$x = 0;}
			$ch .= $k[$x];
			$x++;
		}
		for ($i=0;$i<$len;$i++){
			$str .= chr(ord($data[$i])+(ord($ch[$i]))%256);
		}
		$str = str_replace(array('=','+','/'),array('O00','0O0','O0O'),base64_encode($str));
		return $str;
	}
	
	//解密
	function decrypt($str,$type='base64'){return $this->decode($str,$type);}
	function decode($str,$type='base64'){
		if($type!='base64'){$str = str_replace(array('0o0','0_0','-_-'),array('+','/','='),$str);}
		//php7 采用openssl
		if (floatval(PHP_VERSION)>5.6){
			if (!function_exists('openssl_decrypt')){
				$str	= 	$this->foundphp_decrypt($str,$this->key);
			}else{
				$str	= openssl_decrypt(base64_decode($str),'AES-256-CBC',substr($this->key,0,32),OPENSSL_RAW_DATA,substr($this->iv,0,16));
			}
		}else{
			if ($this->type=='aes'){
				$module		= mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
				mcrypt_generic_init($module, $this->key, $this->iv);
				$str		= mdecrypt_generic($module, base64_decode($str));
			}else{
				$str		= @mcrypt_cbc(MCRYPT_DES,$this->key,base64_decode($str),MCRYPT_DECRYPT,$this->iv);
				$pad		= @ord($str[(strlen($str)-1)]);
				if($pad > strlen($str)){return false;}
				if(strspn($str,chr($pad), strlen($str)-$pad)!=$pad){return false;}
				$str 		= substr($str, 0, - 1 * $pad);
			}
		}
		return $str;
	}
	function foundphp_decrypt($data, $key){
		$k		= substr(md5($key),10,-10);
		$x		= 0;
		$data	= base64_decode(str_replace(array('O00','0O0','O0O'),array('=','+','/'),$data));
		$len	= strlen($data);
		$l		= strlen($k);
		$ch=$str= '';
		for ($i=0;$i<$len;$i++){
			if ($x==$l){$x=0;}
			$ch .= substr($k,$x,1);
			$x++;
		}
		for ($i=0;$i<$len;$i++){
			if (ord(substr($data,$i,1))<ord(substr($ch,$i,1))){
				$str .= chr((ord(substr($data,$i,1))+256)-ord(substr($ch,$i,1)));
			}else{
				$str .= chr(ord(substr($data,$i,1))-ord(substr($ch,$i,1)));
			}
		}
		return $str;
	}
}
?>