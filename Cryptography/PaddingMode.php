<?php
namespace Cryptography;

/**
 * Specifies the type of padding to apply when the message data block is shorter than the full number of bytes needed for a cryptographic operation
 * @author ludovic.senecaux
 *
 */
final class PaddingMode
{
    const None  = 0;
    const PKCS7 = 1;
    const Zeros = 2;
    const ANSIX923 = 3;
    const ISO10126 = 4;
}
