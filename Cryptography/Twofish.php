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
    public static function Create()
    {
        $object = new Twofish();
        $object->_properties = array(
            parent::KEY_SIZE_128,
            parent::KEY_SIZE_192,
            parent::KEY_SIZE_156
        );
        $object->KeySize = parent::KEY_SIZE_128;

        // Twofish uses blocks of size 16 (128 bits)
        $object->_cipherAlg = MCRYPT_TWOFISH;
        $object->BlockSize = 16;

        return $object;
    }
}
