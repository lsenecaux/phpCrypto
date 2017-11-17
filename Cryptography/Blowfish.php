<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Blowfish algorithm
 * @author ludovic.senecaux
 *
 */
final class Blowfish extends SymmetricAlgorithm
{
    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\Blowfish
     */
    public static function Create($KeySize = parent::KEY_SIZE_128)
    {
        $object = new Blowfish();
        $object->_properties['LegalKeySizes'] = array_map(function($f) { return $f; }, range(4,56));
        $object->KeySize = $KeySize;

        // Blowfish uses blocks of size 8 (64 bits)
        $object->_cipherAlg = MCRYPT_BLOWFISH;
        $object->BlockSize = 8;

        return $object;
    }   
}
