<?php
namespace Cryptography;

/**
 * Implementations of Hash-based Message Authentication Code (HMAC)
 * @author ludovic.senecaux
 *
 */
final class HMAC extends HashAlgorithm
{
    /**
     * Initializes a new instance of the HMAC class
     */
    public function __construct() 
    {
        parent::__construct();
        
        // Gets or sets the key to use in the hash algorithm
        $this->_properties['Key'] = NULL;
    }
    
    /**
     * Computes the Hash-based Message Authentication Code (HMAC) for the specified data
     * @param string $Data
     * @param boolean $RawOutput
     * @throws \Exception
     * @return string
     */
    public function ComputeHash($Data, $RawOutput = TRUE)
    {
        if ($this->Algorithm == NULL)
            throw new \Exception(sprintf('%s::%s : Hash algorithm cannot be null', self::GetType(), __FUNCTION__));
        
        if ($this->Key == NULL)
          throw new \Exception(sprintf('%s::%s : Key cannot be null', self::GetType(), __FUNCTION__));
        
        return hash_hmac($this->Algorithm, $Data, $this->Key, $RawOutput);
    }
}
?>