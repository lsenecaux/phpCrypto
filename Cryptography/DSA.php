<?php
namespace Cryptography;

/**
 * Provides an implementation of the Digital Signature Algorithm (DSA).
 * @author ludovic.senecaux
 *
 */
final class DSA extends AsymmetricAlgorithm
{
    /**
     * Initializes a new instance of the DSA class with a randomly generated key of the specified size. 
     * @param number $KeySize
     * @return \Cryptography\DSA
     */
    public static function Create($KeySize = 512)
    {
        $object = new DSA();
        $object->_params['private_key_type'] = OPENSSL_KEYTYPE_DSA;
        $object->_properties['LegalKeySizes'] = array_map(function($f) { return pow(2, $f); }, range(9, 12, 1));
        $object->KeySize = $KeySize;
        $object->_GenerateKey();
        $object->_getProperties();
    
        return $object;
    }
    
    /**
     * Initializes a DSA object from the key information from a file. 
     * @param string $FileName
     * @param string $Passphrase
     * @return \Cryptography\DSA
     */
    public static function CreateFromFile($FileName, $Passphrase = NULL)
    {        
        return DSA::CreateFromString(file_get_contents($FileName), $Passphrase);
    }
    
    /**
     * Initializes a DSA object from the key information from a string.
     * @param string $PEM
     * @param string $Passphrase
     * @return \Cryptography\DSA
     */
    public static  function CreateFromString($PEM, $Passphrase = NULL)
    {
        $object = new DSA();
        //$object->_resource = openssl_pkey_get_private($PEM, $Passphrase);
        
        try
        {
            $object->_resource = openssl_pkey_get_private($PEM, $Passphrase);
            $object->_publicOnly = false;
        }
        catch (\Exception $e)
        {
            $object->_resource = openssl_pkey_get_public($PEM);
            $object->_publicOnly = true;
        }
        
        $object->_getProperties();
    
        return $object;
    }
    
    /**
     * Gets key properties.
     */
    private function _getProperties()
    {
        $this->_Export();
        $details = openssl_pkey_get_details($this->_resource);
    
        $this->PublicKey = trim(base64_decode(preg_replace('/-----(BEGIN|END)(.+)PUBLIC KEY-----/i', NULL, $details['key'])));
        $this->KeySize = $details['bits'];
        
        $this->_properties['Params'] = array(
            'P'             => $details['dsa']['p'],
            'Q'             => $details['dsa']['q'],
            'G'             => $details['dsa']['g'],
            'Y'             => $details['dsa']['pub_key'],
            //'X'             => $details['dsa']['priv_key'],                     
        );
        
        if ($this->_publicOnly === FALSE)
            $this->_properties['Params']['X'] = $details['dsa']['priv_key'];        
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \Cryptography\AsymmetricAlgorithm::ToXMLString()
     */
    public function ToXMLString($IncludePrivateParamerters = TRUE)
    {
        $xml = new \DOMDocument('1.0', 'UTF-8');
        $root = $xml->createElement('DSAKeyValue');
    

        foreach ($this->_properties['Params'] as $param => $value)
            $root->appendChild($xml->createElement($param, $value));
        
        if ($IncludePrivateParamerters === FALSE || $this->_publicOnly === TRUE)        
            $root->removeChild($root->getElementsByTagName('X')->item(0));        
    
        $xml->appendChild($root);
    
        return $xml->saveXML();
    }
}