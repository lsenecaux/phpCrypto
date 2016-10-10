<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Advanced Encryption Standard (AES) algorithm
 * @author ludovic.senecaux
 *
 */
final class AES extends SymmetricAlgorithm
{
    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\AES
     */
    public static function Create()
    {
        $object = new AES();
        $object->_properties['LegalKeySizes'] = array(
            parent::KEY_SIZE_128,
            parent::KEY_SIZE_192,
            parent::KEY_SIZE_256,
        );
        $object->KeySize = parent::KEY_SIZE_128;

        // AES uses blocks of size 16 (128 bits)
        $object->_cipherAlg = MCRYPT_RIJNDAEL_128;
        $object->BlockSize = 16;

        return $object;
    }
}
