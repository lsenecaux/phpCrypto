<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Twofish algorithm
 * @author ludovic.senecaux
 *
 */
final class Twofish extends SymmetricAlgorithm
{
    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\Twofish
     */
    public static function Create($KeySize = parent::KEY_SIZE_128)
    {
        $object = new Twofish();
        $object->_properties['LegalKeySizes'] = array(
            parent::KEY_SIZE_128,
            parent::KEY_SIZE_192,
            parent::KEY_SIZE_256
        );
        $object->KeySize = $KeySize;

        // Twofish uses blocks of size 16 (128 bits)
        $object->_cipherAlg = MCRYPT_TWOFISH;
        $object->BlockSize = 16;

        return $object;
    }
}
