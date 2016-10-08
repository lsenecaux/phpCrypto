<?php
namespace Cryptography;

/**
 * Specifies the block cipher mode to use for encryption
 * @author ludovic.senecaux
 *
 */
final class CipherMode
{
    /**
     * Electronic Codebook
     * @var string
     */
    const ECB = 'ecb';
        
    /**
     * Cipher Block Chaining
     * @var string
     */
    const CBC = 'cbc';
    
    /**
     * Cipher Feedback
     * @var string
     */    
    const CFB = 'cfb';
    
    /**
     * Output Feedback
     * @var string
     */
    const OFB = 'ofb';
    
    /**
     * Counter
     * @var string
     */
    const CTR = 'ctr';
}

?>