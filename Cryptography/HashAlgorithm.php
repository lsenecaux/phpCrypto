<?php
namespace Cryptography;

/**
 * Implementations of cryptographic hash algorithms
 * @author ludovic.senecaux
 *
 */
class HashAlgorithm
{
    /**
     * Properties
     * @var array
     */
    protected $_properties;

    /**
     * Initializes a new instance of the Hash class
     */
    public function __construct()
    {
        $this->_properties = array(
            'Algorithm'     => NULL,    // Gets or sets the name of the hash algorithm to use for hashing
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

        if ($Property == 'Algorithm')
            if (!in_array(strtolower($Value), self::GetAlgorithms()))
                throw new \Exception(sprintf('%s : Hash algorithm %s is not supported', self::GetType(), self::GetType(), $Value));

        $this->_properties[$Property] = strtolower($Value);
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
     * Computes the hash value for the specified data
     * @param string $Data
     * @param boolean $RawOuput
     * @throws \Exception
     * @return string
     */
    public function ComputeHash($Data, $RawOuput = TRUE)
    {
        if ($this->Algorithm == NULL)
            throw new \Exception(sprintf('%s::%s : Hash algorithm cannot be null', self::GetType(), __FUNCTION__));
            
        return hash($this->Algorithm, $Data, $RawOuput);
    }

    /**
     * Get a list of registered hashing algorithms
     * @return array
     */
    public static function GetAlgorithms()
    {
        return hash_algos();
    }

    /**
     * Gets the block size of the specified hash algorithm
     * @param string $Algorithm
     * @throws \Exception
     * @return integer
     */
    public static function GetBlockSize($Algorithm)
    {
        if (!in_array(strtolower($Algorithm), self::GetAlgorithms()))
            throw new \Exception(sprintf('%s::%s : Hash algorithm %s is not supported yet', __METHOD__, $Algorithm));

        return strlen(hash(strtolower($Algorithm), NULL, true));
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
     * @return \Cryptography\HMAC
     */
    public function Copy()
    {
        return clone $this;
    }
}
