<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Serpent algorithm
 * @author ludovic.senecaux
 *
 */
final class Serpent extends SymmetricAlgorithm
{
    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\Serpent
     */
    public static function Create()
    {
        $object = new Serpent();
        $object->_properties['LegalKeySizes'] = array(
            parent::KEY_SIZE_128,
            parent::KEY_SIZE_192,
            parent::KEY_SIZE_256
        );
        $object->KeySize = parent::KEY_SIZE_128;
        
        // Serpent uses blocks of size 16 (128 bits)
        $object->_cipherAlg = MCRYPT_SERPENT;
        $object->BlockSize = 16;
        
        return $object;
    }   
}
