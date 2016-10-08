<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Serpent algorithm
 * @author ludovic.senecaux
 *
 */
final class Serpent extends SymmetricAlgorithm
{
    const SERPENT_128 = 16;
    const SERPENT_192 = 24;
    const SERPENT_256 = 32;
    
    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\Serpent
     */
    public static function Create()
    {
        $object = new Serpent();
        $object->KeySize = self::SERPENT_128;
        
        // Serpent uses blocks of size 16 (128 bits)
        $object->_cipherAlg = MCRYPT_SERPENT;
        $object->BlockSize = 16;
        
        return $object;
    }
    
    /**
     * @see \Cryptography\SymmetricAlgorithm::GenerateIV()
     */
    public function GenerateIV()
    {
        if ($this->BlockSize != 16)
            throw new \Exception(sprintf('%s : Block of size %d not supported by this algorithm. Only blocks of size 16 are supported', __METHOD__, $this->BlockSize));
    
        parent::GenerateIV();
    }
    
    /**
     * @see \Cryptography\SymmetricAlgorithm::GenerateKey()
     */
    public function GenerateKey()
    {
        switch ($this->KeySize)
        {
            case self::SERPENT_128:
            case self::SERPENT_192:
            case self::SERPENT_256:
                parent::GenerateKey();
                break;
    
            default:
                throw new \Exception(sprintf('%s : Key of size %d not supported by this algorithm. Only keys of sizes 16, 24 or 32 are supported', __METHOD__, $this->KeySize));
        }
    }
}
