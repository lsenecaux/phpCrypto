<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Twofish algorithm
 * @author ludovic.senecaux
 *
 */
final class Twofish extends SymmetricAlgorithm
{
    const TWOFISH_128 = 16;
    const TWOFISH_192 = 24;
    const TWOFISH_256 = 32;

    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\Twofish
     */
    public static function Create()
    {
        $object = new Twofish();
        $object->KeySize = self::TWOFISH_128;

        // Twofish uses blocks of size 16 (128 bits)
        $object->_cipherAlg = MCRYPT_TWOFISH;
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
            case self::TWOFISH_128:
            case self::TWOFISH_192:
            case self::TWOFISH_256:
                parent::GenerateKey();
                break;

            default:
                throw new \Exception(sprintf('%s : Key of size %d not supported by this algorithm. Only keys of sizes 16, 24 or 32 are supported', __METHOD__, $this->KeySize));
        }
    }
}
