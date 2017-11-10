<?php

require_once 'Cryptography/SymmetricAlgorithm.php';
require_once 'Cryptography/AES.php';
require_once 'Cryptography/CipherMode.php';
require_once 'Cryptography/PaddingMode.php';

require_once 'Cryptography/AsymmetricAlgorithm.php';
require_once 'Cryptography/RSA.php';

// Symmetric
$object = \Cryptography\AES::Create();
$object->KeySize = \Cryptography\SymmetricAlgorithm::KEY_SIZE_256;
$object->Mode = \Cryptography\CipherMode::CBC;
$object->Padding = \Cryptography\PaddingMode::PKCS7;
$object->GenerateKey();
$object->GenerateIV();
$cipher = $object->Encrypt('Hello, world!');
$plaintext = $object->Decrypt($cipher);

// Asymmetric
$object = \Cryptography\RSA::Create(2048);
$data = 'Hello, world!';
$sign = $object->Sign($data);
$verify = $object->Verify($data, $sign);
$encData = $object->Encrypt($data);
$plainData = $object->Decrypt($encData);

?>
