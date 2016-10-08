<?php
namespace Cryptography;

/**
 * Performs symmetric encryption and decryption using the Blowfish algorithm
 * @author ludovic.senecaux
 *
 */
final class Blowfish extends SymmetricAlgorithm
{
    const BLOWFISH_32 = 4;
    const BLOWFISH_40 = 5;
    const BLOWFISH_48 = 6;
    const BLOWFISH_56 = 7;
    const BLOWFISH_64 = 8;
    const BLOWFISH_72 = 9;
    const BLOWFISH_80 = 10;
    const BLOWFISH_88 = 11;
    const BLOWFISH_96 = 12;
    const BLOWFISH_104 = 13;
    const BLOWFISH_112 = 14;
    const BLOWFISH_120 = 15;
    const BLOWFISH_128 = 16;
    const BLOWFISH_136 = 17;
    const BLOWFISH_144 = 18;
    const BLOWFISH_152 = 19;
    const BLOWFISH_160 = 20;
    const BLOWFISH_168 = 21;
    const BLOWFISH_176 = 22;
    const BLOWFISH_184 = 23;
    const BLOWFISH_192 = 24;
    const BLOWFISH_200 = 25;
    const BLOWFISH_208 = 26;
    const BLOWFISH_216 = 27;
    const BLOWFISH_224 = 28;
    const BLOWFISH_232 = 29;
    const BLOWFISH_240 = 30;
    const BLOWFISH_248 = 31;
    const BLOWFISH_256 = 32;
    const BLOWFISH_264 = 33;
    const BLOWFISH_272 = 34;
    const BLOWFISH_280 = 35;
    const BLOWFISH_288 = 36;
    const BLOWFISH_296 = 37;
    const BLOWFISH_304 = 38;
    const BLOWFISH_312 = 39;
    const BLOWFISH_320 = 40;
    const BLOWFISH_328 = 41;
    const BLOWFISH_336 = 42;
    const BLOWFISH_344 = 43;
    const BLOWFISH_352 = 44;
    const BLOWFISH_360 = 45;
    const BLOWFISH_368 = 46;
    const BLOWFISH_376 = 47;
    const BLOWFISH_384 = 48;
    const BLOWFISH_392 = 49;
    const BLOWFISH_400 = 50;
    const BLOWFISH_408 = 51;
    const BLOWFISH_416 = 52;
    const BLOWFISH_424 = 53;
    const BLOWFISH_432 = 54;
    const BLOWFISH_440 = 55;
    const BLOWFISH_448 = 56;
    

    /**
     * Creates a cryptographic object that is used to perform the symmetric algorithm
     * @return \Cryptography\Blowfish
     */
    public static function Create()
    {
        $object = new Blowfish();
        $object->KeySize = self::BLOWFISH_128;

        // Blowfish uses blocks of size 8 (64 bits)
        $object->_cipherAlg = MCRYPT_BLOWFISH;
        $object->BlockSize = 8;

        return $object;
    }

    /**
     * @see \Cryptography\SymmetricAlgorithm::GenerateIV()
     */
    public function GenerateIV()
    {
        if ($this->BlockSize != 8)
            throw new \Exception(sprintf('%s : Block of size %d not supported by this algorithm. Only blocks of size 8 are supported', __METHOD__, $this->BlockSize));

        parent::GenerateIV();
    }

    /**
     * @see \Cryptography\SymmetricAlgorithm::GenerateKey()
     */
    public function GenerateKey()
    {
        if ($this->KeySize < 4 || $this->KeySize > 56)
            throw new \Exception(sprintf('%s : Key of size %d not supported by this algorithm. Only keys of sizes from 4 to 56 are supported', __METHOD__, $this->KeySize));

        parent::GenerateKey();
    }
}
