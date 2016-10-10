# phpCrypto
Provides cryptographic classes for PHP

### Symmetric Algorithm
- AES
- Serpent
- Twofish
- Blowfish

### Hashing
- Hash
- HMAC

### Examples
<?php
$object = \Cryptography\AES::Create();
$object->KeySize = \Cryptography\SymmetricAlgorithm::KEY_SIZE_256;
$object->Mode = \Cryptography\CipherMode::CBC;
$object->Padding = \Cryptography\PaddingMode::PKCS7;
$object->GenerateKey();
$object->GenerateIV();
$cipher = $object->Encrypt('Hello, world!');
$plaintext = $object->Decrypt($cipher);
?>
