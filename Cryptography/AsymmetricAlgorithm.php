<?php
namespace Cryptography;

/**
 * Represents the abstract base class from which all implementations of asymmetric algorithms must inherit.
 * @author ludovic.senecaux
 *
 */
abstract class AsymmetricAlgorithm
{
    /**
     * Key Properties
     * @var array
     */
    protected $_properties;
    
    /**
     * Key Parameters
     * @var array
     */
    protected $_params;
    
    /**
     * Key Resource
     * @var resource
     */
    protected $_resource;
    
    /**
     * Is a public key only ?
     * @var boolean
     */
    protected $_publicOnly;
    
    /**
     * Initializes a new instance of the AsymmetricAlgorithm class
     */
    protected function __construct()
    {
        $this->_properties = array(
            'KeySize'       => NULL,
            'PublicKey'     => NULL,
            'LegalKeySizes' => NULL,
            'Key'           => NULL,
        );
        
        $this->_params = array(
            'private_key_type'  => NULL,
            'private_key_bits'  => NULL,
        );
    }
    
    /**
     * Sets a property
     * @param string $Property
     * @param mixed $Value
     * @throws \Exception
     */
    public function __set($Property, $Value)
    {
        if (!array_key_exists($Property, $this->_properties))
            throw new \Exception(sprintf('%s::%s : This is not a valid property', self::GetType(), $Property));
        
        if ($Property == 'Key' || $Property == 'LegalKeySizes')
            throw new \Exception(sprintf('%s::%s : This is a read only property', self::GetType(), $Property));
        
        if ($Property == 'KeySize' && !in_array($Value, $this->LegalKeySizes))
            throw new \Exception(sprintf('%s::%s : Key of size %d not supported by this algorithm. Only keys of size %s are supported', self::GetType(), $Property, $Value, implode(', ', $this->LegalKeySizes)));            
        
        if ($Property == 'KeySize')
            $this->_params['private_key_bits'] = $Value;
                  
        $this->_properties[$Property] = $Value;
    }
    
    /**
     * Gets a property
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
     * Computes the hash value of the specified data using the specified hash algorithm and signs the resulting hash value.
     * @param string $Data
     * @param string $HashAlgo
     * @throws \Exception
     * @return string
     */
    public function Sign($Data, $HashAlgo = 'SHA1')
    {
        if ($this->_publicOnly === TRUE)
            throw new \Exception('This is a public key, data cannot be signed !');
        
        if (!in_array($HashAlgo, openssl_get_md_methods()))
            throw new \Exception(sprintf('%s is not a valid hash algorithm', $HashAlgo));
    
        if (!openssl_sign($Data, $SignedData, $this->_resource, $HashAlgo))
            throw new \Exception('An error occured while signing data');
    
        return $SignedData;
    }
    
    /**
     * Verifies that a digital signature is valid by calculating the hash value of the specified data using the specified hash algorithm and comparing it to the provided signature.
     * @param string $Data
     * @param string $Signature
     * @param string $HashAlgo
     * @throws \Exception
     * @return boolean
     */
    public function Verify($Data, $Signature, $HashAlgo = 'SHA1')
    {
        if (!in_array($HashAlgo, openssl_get_md_methods()))
            throw new \Exception(sprintf('%s is not a valid hash algorithm', $HashAlgo));
    
        $result = openssl_verify($Data, $Signature, sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", base64_encode($this->PublicKey)), $HashAlgo);
        if ($result === -1)
            throw new \Exception('An error occured while verifying signature');
    
        return $result === 1 ? true : false;
    }
    
    /**
     * Creates and returns an XML string containing the key of the current object.
     */
    public abstract function ToXMLString();
    
    /**
     * Generates a public/private key pair to use for the algorithm.
     * @throws \Exception
     */
    protected function _GenerateKey()
    {
        $this->_resource = openssl_pkey_new($this->_params);
    }
    
    /**
     * Gets an exportable representation of a key into a string.
     */
    protected function _Export()
    {
        openssl_pkey_export($this->_resource, $key);
        $this->_properties['Key'] = base64_decode(trim(preg_replace('/-----(BEGIN|END)(.+)PRIVATE KEY-----/i', NULL, $key)));
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
     * @return \Cryptography\AsymmetricAlgorithm
     */
    public function Copy()
    {
        return clone $this;
    }
}
