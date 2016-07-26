<?php
namespace Ci2Lara\Codeigniter_Migration\Services;

use Cookie;
use Ci2Lara\Codeigniter_Migration\Models\CodeigniterSession;


class CodeigniterService
{
	protected $_hash_type		= 'sha1';
	
	/**
	 * Current cipher to be used with mcrypt
	 *
	 * @var string
	 */
	protected $_mcrypt_cipher;

	/**
	 * Method for encrypting/decrypting data
	 *
	 * @var int
	 */
	protected $_mcrypt_mode;
	
    public function __construct() 
    {
        $cookieName = config('ci_session.sess_cookie_name');
        $cookieValue = Cookie::get($cookieName);
        
        $ciSession = unserialize($this->decode($cookieValue));
        
        if (isset($ciSession) && isset($ciSession['session_id'])) {
            $sess = CodeigniterSession::find($ciSession['session_id']);
            $this->setUserData($sess);
        }
    }


    public function setUserData($data)
    {
        $this->sessionData = $data;
        $this->userData = !is_null($this->sessionData) ? unserialize($this->sessionData->user_data) : null;
    }

    public function getUserData()
    {
        if (isset($this->userData)) {
            return $this->userData;
        } else {
            return null;
        }
    }

    public function getConfigData()
    {
        if (isset($this->userData['ci_config'])) {
            return (object) $this->userData['ci_config'];
        } else {
            return null;
        }
    }
    
    private function decode($string)
	{
		if (preg_match('/[^a-zA-Z0-9\/\+=]/', $string) OR base64_encode(base64_decode($string)) !== $string)
		{
			return $string;
		}
		
		if ( config('ci_session.sess_key') == '' ) {
			return $string;
		}

		return $this->mcrypt_decode(base64_decode($string), md5(config('ci_session.sess_key')));
	}

	/**
	 * Decrypt using Mcrypt
	 *
	 * @param	string
	 * @param	string
	 * @return	string
	 */
	private function mcrypt_decode($data, $key)
	{
		$data = $this->_remove_cipher_noise($data, $key);
		
		$init_size = mcrypt_get_iv_size($this->_get_cipher(), $this->_get_mode());

		if ($init_size > strlen($data))
		{
			return FALSE;
		}

		$init_vect = substr($data, 0, $init_size);
		$data = substr($data, $init_size);
		return rtrim(mcrypt_decrypt($this->_get_cipher(), $key, $data, $this->_get_mode(), $init_vect), "\0");
	}
	
	// --------------------------------------------------------------------

	/**
	 * Removes permuted noise from the IV + encrypted data, reversing
	 * _add_cipher_noise()
	 *
	 * Function description
	 *
	 * @param	string	$data
	 * @param	string	$key
	 * @return	string
	 */
	protected function _remove_cipher_noise($data, $key)
	{
		$key = $this->hash($key);
		$str = '';

		for ($i = 0, $j = 0, $ld = strlen($data), $lk = strlen($key); $i < $ld; ++$i, ++$j)
		{
			if ($j >= $lk)
			{
				$j = 0;
			}

			$temp = ord($data[$i]) - ord($key[$j]);

			if ($temp < 0)
			{
				$temp += 256;
			}

			$str .= chr($temp);
		}

		return $str;
	}
	
	/**
	 * Hash encode a string
	 *
	 * @param	string
	 * @return	string
	 */
	public function hash($str)
	{
		return hash($this->_hash_type, $str);
	}

	/**
	 * Set the Mcrypt Cipher
	 *
	 * @param	int
	 * @return	CI_Encrypt
	 */
	public function set_cipher($cipher)
	{
		$this->_mcrypt_cipher = $cipher;
		return $this;
	}
	
	/**
	 * Get Mcrypt cipher Value
	 *
	 * @return	int
	 */
	protected function _get_cipher()
	{
		if ($this->_mcrypt_cipher === NULL)
		{
			return $this->_mcrypt_cipher = MCRYPT_RIJNDAEL_256;
		}

		return $this->_mcrypt_cipher;
	}
	
	/**
	 * Get Mcrypt Mode Value
	 *
	 * @return	int
	 */
	protected function _get_mode()
	{
		if ($this->_mcrypt_mode === NULL)
		{
			return $this->_mcrypt_mode = MCRYPT_MODE_CBC;
		}

		return $this->_mcrypt_mode;
	}
    
}
