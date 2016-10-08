<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Advanced Encryption Standard (AES) algorithm
 * @author ludovic.senecaux
 *
 */
final class AES extends SymmetricAlgorithm
{
    const AES_128 = 16;
    const AES_192 = 24;
    const AES_256 = 32;

    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\AES
     */
    public static function Create()
    {
        $object = new AES();

        $object->KeySize = self::AES_128;

        // AES uses blocks of size 16 (128 bits)
        $object->_cipherAlg = MCRYPT_RIJNDAEL_128;
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
            case self::AES_128:
            case self::AES_192:
            case self::AES_256:
                parent::GenerateKey();
                break;

            default:
                throw new \Exception(sprintf('%s : Key of size %d not supported by this algorithm. Only keys of sizes 16, 24 or 32 are supported', __METHOD__, $this->KeySize));
        }
    }
}

?>