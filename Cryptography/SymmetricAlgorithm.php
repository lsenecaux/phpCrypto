<?php
namespace Cryptography;

/**
 * Represents the abstract base class from which all implementations of symmetric algorithms must inherit.
 * @author ludovic.senecaux
 *
 */
abstract class SymmetricAlgorithm
{
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
            'BlockSize'     => NULL,                // Gets or sets the block size, in bits, of the cryptographic operation
            'KeySize'       => NULL,                // Gets or sets the size, in bits, of the secret key used by the symmetric algorithm
            'Key'           => NULL,                // Gets or sets the secret key for the symmetric algorithm
            'IV'            => NULL,                // Gets or sets the initialization vector (IV) for the symmetric algorithm
            'Mode'          => CipherMode::CBC,		// Gets or sets the mode for operation of the symmetric algorithm
            'PaddingMode'   => PaddingMode::PKCS7   // Gets or sets the padding mode used in the symmetric algorithm
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
            throw new \Exception(sprintf('%s::%s is not a valid property !', self::GetType(), $Property));
        
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
        if ($this->BlockSize == NULL)
            throw new \Exception(sprintf('%s::%s : Block size cannot be null', self::GetType(), __FUNCTION__));        
        
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
        
        switch ($this->PaddingMode)
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
        switch ($this->PaddingMode)
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
                    throw new \Exception(sprintf('%s::%s : Zeros padding found instead of %s padding', self::GetType(), __FUNCTION__, array_search($this->PaddingMode, (new ReflectionClass('PaddingMode'))->getConstants())));

                if ($padSize > $this->BlockSize)
                    throw new \Exception(sprintf('%s::%s : Incorrect amount of %s padding for block size', self::GetType(), __FUNCTION__, array_search($this->PaddingMode, (new ReflectionClass('PaddingMode'))->getConstants())));

                switch ($this->PaddingMode)
                {
                    case PaddingMode::PKCS7:
                        if (substr_count(substr($Data, -1 * $padSize), chr($padSize)) != $padSize)
                            throw new \Exception(sprintf('%s::%s : Invalid %s padding encountered', self::GetType(), __FUNCTION__, array_search($this->PaddingMode, (new ReflectionClass('PaddingMode'))->getConstants())));                        
                        break;
                        
                    case PaddingMode::ANSIX923:
                        if (substr_count(substr($Data, -1 * $padSize, -1), chr(0)) != $padSize - 1)
                            throw new \Exception(sprintf('%s::%s : Invalid %s padding encountered', self::GetType(), __FUNCTION__, array_search($this->PaddingMode, (new ReflectionClass('PaddingMode'))->getConstants())));                        
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
