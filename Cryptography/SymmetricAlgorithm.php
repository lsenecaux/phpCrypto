<?php
namespace Cryptography;

/**
 * Represents the abstract base class from which all implementations of symmetric algorithms must inherit.
 * @author ludovic.senecaux
 *
 */
abstract class SymmetricAlgorithm
{
    const KEY_SIZE_32 = 4;
    const KEY_SIZE_40 = 5;
    const KEY_SIZE_48 = 6;
    const KEY_SIZE_56 = 7;
    const KEY_SIZE_64 = 8;
    const KEY_SIZE_72 = 9;
    const KEY_SIZE_80 = 10;
    const KEY_SIZE_88 = 11;
    const KEY_SIZE_96 = 12;
    const KEY_SIZE_104 = 13;
    const KEY_SIZE_112 = 14;
    const KEY_SIZE_120 = 15;
    const KEY_SIZE_128 = 16;
    const KEY_SIZE_136 = 17;
    const KEY_SIZE_144 = 18;
    const KEY_SIZE_152 = 19;
    const KEY_SIZE_160 = 20;
    const KEY_SIZE_168 = 21;
    const KEY_SIZE_176 = 22;
    const KEY_SIZE_184 = 23;
    const KEY_SIZE_192 = 24;
    const KEY_SIZE_200 = 25;
    const KEY_SIZE_208 = 26;
    const KEY_SIZE_216 = 27;
    const KEY_SIZE_224 = 28;
    const KEY_SIZE_232 = 29;
    const KEY_SIZE_240 = 30;
    const KEY_SIZE_248 = 31;
    const KEY_SIZE_256 = 32;
    const KEY_SIZE_264 = 33;
    const KEY_SIZE_272 = 34;
    const KEY_SIZE_280 = 35;
    const KEY_SIZE_288 = 36;
    const KEY_SIZE_296 = 37;
    const KEY_SIZE_304 = 38;
    const KEY_SIZE_312 = 39;
    const KEY_SIZE_320 = 40;
    const KEY_SIZE_328 = 41;
    const KEY_SIZE_336 = 42;
    const KEY_SIZE_344 = 43;
    const KEY_SIZE_352 = 44;
    const KEY_SIZE_360 = 45;
    const KEY_SIZE_368 = 46;
    const KEY_SIZE_376 = 47;
    const KEY_SIZE_384 = 48;
    const KEY_SIZE_392 = 49;
    const KEY_SIZE_400 = 50;
    const KEY_SIZE_408 = 51;
    const KEY_SIZE_416 = 52;
    const KEY_SIZE_424 = 53;
    const KEY_SIZE_432 = 54;
    const KEY_SIZE_440 = 55;
    const KEY_SIZE_448 = 56;
    const KEY_SIZE_456 = 57;
    const KEY_SIZE_464 = 58;
    const KEY_SIZE_472 = 59;
    const KEY_SIZE_480 = 60;
    const KEY_SIZE_488 = 61;
    const KEY_SIZE_496 = 62;
    const KEY_SIZE_504 = 63;
    const KEY_SIZE_512 = 64;
    
    /**
     * Properties
     * @var array
     */
    protected $_properties;
    
    /**
     * Cipher Algorithm
     * @var string
     */
    protected $_cipherAlg; 
    
    /**
     * Initializes a new instance of the SymmetricAlgorithm class
     */
    protected function __construct()
    {
        $this->_properties = array(
            'BlockSize'     => NULL,                // Represents the block size, in bits, of the cryptographic operation
            'LegalKeySizes' => NULL,                // Specifies the key sizes, in bits, that are supported by the symmetric algorithm
            'KeySize'       => NULL,                // Represents the size, in bits, of the secret key used by the symmetric algorithm
            'Key'           => NULL,                // Represents the secret key for the symmetric algorithm
            'IV'            => NULL,                // Represents the initialization vector (IV) for the symmetric algorithm
            'Mode'          => CipherMode::CBC,		// Represents the cipher mode used in the symmetric algorithm
            'Padding'       => PaddingMode::PKCS7   // Represents the padding mode used in the symmetric algorithm
        );
    }
    
    /**
     * Set a property
     * @param string $Property
     * @param mixed $Value
     * @throws \Exception
     */
    public function __set($Property, $Value)
    {
        if (!array_key_exists($Property, $this->_properties))
            throw new \Exception(sprintf('%s::%s : This is not a valid property', self::GetType(), $Property));
        
        if ($Property == 'LegalKeySizes')
            throw new \Exception(sprintf('%s::%s : This is a read only property', self::GetType(), $Property));
        
        if ($Property == 'BlockSize' && $Value != ($requiredBlockSize = mcrypt_get_block_size($this->_cipherAlg, $this->Mode)))
            throw new \Exception(sprintf('%s::%s : Block of size %d not supported by this algorithm. Only blocks of size %d are supported', self::GetType(), $Property, $Value, $requiredBlockSize));

        if ($Property == 'KeySize' && !in_array($Value, $this->LegalKeySizes))
            throw new \Exception(sprintf('%s::%s : Key of size %d not supported by this algorithm. Only keys of size %s are supported', self::GetType(), $Property, $Value, implode(', ', $this->LegalKeySizes)));
        
        if ($Property == 'Padding' && !in_array($Value, (new \ReflectionClass('\Cryptography\PaddingMode'))->getConstants()))
            throw new \Exception(sprintf('%s::%s : Padding value %d is not supported. Only padding values %s are supported', self::GetType(), $Property, $Value, implode(', ', (array_flip((new \ReflectionClass('\Cryptography\PaddingMode'))->getConstants())))));
        
        $this->_properties[$Property] = $Value;
    }
    
    /**
     * Get a property
     * @param string $Property
     * @throws \Exception
     * @return mixed
     */
    public function __get($Property)
    {
        if (!array_key_exists($Property, $this->_properties))
            throw new \Exception(sprintf('%s::%s is not a valid property !', self::GetType(), $Property));
        
        return $this->_properties[$Property];
    }
    
    /**
     * Generates a random key (Key) to use for the algorithm
     * @throws \Exception
     */
    public function GenerateKey() 
    {
        if ($this->KeySize == NULL)
            throw new \Exception(sprintf('%s::%s : Key size cannot be null', self::GetType(), __FUNCTION__));
        
        $this->Key = mcrypt_create_iv($this->KeySize, MCRYPT_RAND);        
    }
    
    /**
     * Generates a random initialization vector (IV) to use for the algorithm
     * @throws \Exception
     */
    public function GenerateIV()
    {
        if (($ivSize = @mcrypt_get_iv_size($this->_cipherAlg, $this->Mode)) != $this->BlockSize)
            throw new \Exception(sprintf('%s::%s : The required IV size is %d, and must match the block size (%d)', self::GetType(), __FUNCTION__, $ivSize, $this->BlockSize));
        
        $this->IV = mcrypt_create_iv($this->BlockSize, MCRYPT_RAND);
    }
    
    /**
     * Encrypt the input data          
     * @param string $Data
     * @param boolean $RawOutput
     * @throws \Exception
     * @return string
     */
    public function Encrypt($Data, $RawOutput = TRUE)
    {
        if ($this->IV == NULL)
            throw new \Exception(sprintf('%s::%s : IV must be initialized', self::GetType(), __FUNCTION__));
    
        if ($this->Key == NULL)
            throw new \Exception(sprintf('%s::%s : Key must be initialized', self::GetType(), __FUNCTION__));
                    
        $cipher = mcrypt_encrypt($this->_cipherAlg, $this->Key, self::_pad($Data), $this->Mode, $this->IV);
    
        return ($RawOutput === TRUE) ? $cipher : base64_encode($cipher);
    }
    
    /**
     * Decrypt the input data
     * @param string $Data 
     * @param boolean $RawInput
     * @throws \Exception
     * @return string
     */
    public function Decrypt($Data, $RawInput = TRUE)
    {
        if ($this->IV == NULL)
            throw new \Exception(sprintf('%s::%s : IV must be initialized', self::GetType(), __FUNCTION__));
    
        if ($this->Key == NULL)
            throw new \Exception(sprintf('%s::%s : Key must be initialized', self::GetType(), __FUNCTION__));
    
        $message = mcrypt_decrypt($this->_cipherAlg, $this->Key, (($RawInput === TRUE) ? $Data : base64_decode($Data)), $this->Mode, $this->IV);

        return self::_unpad($message);
    }
    
    /**
     * Right-pads the input data according to the Padding Mode
     * @param string $Data
     * @return string
     */
    private function _pad($Data)
    {        
        $padSize = $this->BlockSize - (strlen($Data) % $this->BlockSize);
        $padString = '';
        
        switch ($this->Padding)
        {
            case PaddingMode::None:
                $padString = '';
                break;
                
            case PaddingMode::Zeros:
                $padString = str_repeat(chr(0), $padSize);
                break;
                
            case PaddingMode::PKCS7:
                $padString = str_repeat(chr($padSize), $padSize);
                break;
                
            case PaddingMode::ANSIX923:
                $padString = str_repeat(chr(0), $padSize - 1) . chr($padSize);
                break;
                
            case PaddingMode::ISO10126:
                $padString = str_repeat(chr(mt_rand(0, 255)), $padSize - 1) . chr($padSize);
                break;
        }
        
        return $Data . $padString;
    }
    
    /**
     * Validates and unpads the input data according to the Padding Mode
     * @param string $Data
     * @return string
     */
    private function _unpad($Data)
    {
        switch ($this->Padding)
        {
            case PaddingMode::None:
                return $Data;
        
            case PaddingMode::Zeros:
                $dataLength = strlen($Data);
                
                if (($dataLength % $this->BlockSize) != 0)
                    throw new \Exception(sprintf('%s::%s : Input data cannot be devided by the block size', self::GetType(), __FUNCTION__));
                
                if (ord($Data[$dataLength - 1]) !== 0)
                    throw new \Exception(sprintf('%s::%s : The padding is different from zeros or there is no padding', self::GetType(), __FUNCTION__));
                
                return rtrim($Data, chr(0));

            case PaddingMode::PKCS7:
            case PaddingMode::ANSIX923:
            case PaddingMode::ISO10126:
                $dataLength = strlen($Data);

                if (($dataLength % $this->BlockSize) != 0)
                    throw new \Exception(sprintf('%s::%s : Input data cannot be devided by the block size', self::GetType(), __FUNCTION__));

                $padSize = ord($Data[$dataLength - 1]);

                if ($padSize === 0)
                    throw new \Exception(sprintf('%s::%s : Zeros padding found instead of %s padding', self::GetType(), __FUNCTION__, array_search($this->Padding, (new \ReflectionClass('\Cryptography\PaddingMode'))->getConstants())));

                if ($padSize > $this->BlockSize)
                    throw new \Exception(sprintf('%s::%s : Incorrect amount of %s padding for block size', self::GetType(), __FUNCTION__, array_search($this->Padding, (new \ReflectionClass('\Cryptography\PaddingMode'))->getConstants())));

                switch ($this->Padding)
                {
                    case PaddingMode::PKCS7:
                        if (substr_count(substr($Data, -1 * $padSize), chr($padSize)) != $padSize)
                            throw new \Exception(sprintf('%s::%s : Invalid %s padding encountered', self::GetType(), __FUNCTION__, array_search($this->Padding, (new \ReflectionClass('\Cryptography\PaddingMode'))->getConstants())));                        
                        break;
                        
                    case PaddingMode::ANSIX923:
                        if (substr_count(substr($Data, -1 * $padSize, -1), chr(0)) != $padSize - 1)
                            throw new \Exception(sprintf('%s::%s : Invalid %s padding encountered', self::GetType(), __FUNCTION__, array_search($this->Padding, (new \ReflectionClass('\Cryptography\PaddingMode'))->getConstants())));                        
                        break;
                }
                
                return substr($Data, 0, $dataLength - $padSize);
        }
    }
    
    /**
     * Returns a string that represents the current object
     * @return string
     */
    public function ToString()
    {
        return serialize($this);
    }
    
    /**
     * Gets the Type of the current instance 
     * @return string
     */
    public function GetType()
    {
        return get_class($this);
    }
    
    /**
     * Determines whether the specified object is equal to the current object
     * @param mixed $Object
     * @return boolean
     */
    public function Equals($Object)
    {
        if (!is_a($Object, self::GetType()))
            return false;
        
        return ($Object->GetHashCode() === self::GetHashCode()) ? true : false;
    }
    
    /**
     * Gets the hash code of the current object
     * @return string
     */
    public function GetHashCode()
    {         
        return sha1(self::ToString(), false);
    }
    
    /**
     * Create a shallow copy of the current object
     * @return \Cryptography\SymmetricAlgorithm
     */
    public function Copy()
    {
        return clone $this;
    }
}
