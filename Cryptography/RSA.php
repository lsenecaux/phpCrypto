<?php
namespace Cryptography;

/**
 * Provides an implementation of the RSA algorithm.
 * @author ludovic.senecaux
 *
 */
final class RSA extends AsymmetricAlgorithm
{
    /**
     * Initializes a new instance of the RSA class with a randomly generated key of the specified size.
     * @param int $KeySize
     * @return \Cryptography\RSA
     */
    public static function Create($KeySize = 1024)
    {
        $object = new RSA();
        $object->_params['private_key_type'] = OPENSSL_KEYTYPE_RSA;
        $object->_properties['LegalKeySizes'] = array_map(function($f) { return pow(2, $f); }, range(9, 14, 1));
        $object->KeySize = $KeySize;
        $object->_GenerateKey();
        $object->_getProperties();
        $object->_publicOnly = false;

        return $object;
    }

    /**
     * Initializes an RSA object from the key information from a file.
     * @param string $FileName
     * @param string $Passphrase
     * @return \Cryptography\RSA
     */
    public static function CreateFromFile($FileName, $Passphrase = NULL)
    {
        return RSA::CreateFromString(file_get_contents($FileName), $Passphrase);
    }

    /**
     * Initializes an RSA object from the key information from a string.
     * @param string $PEM
     * @param string $Passphrase
     * @return \Cryptography\RSA
     */
    public static function CreateFromString($PEM, $Passphrase = NULL)
    {
        $object = new RSA();
        
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

        $this->PublicKey = base64_decode(trim(preg_replace('/-----(BEGIN|END)(.+)PUBLIC KEY-----/i', NULL, $details['key'])));
        $this->KeySize = $details['bits'];


        $this->_properties['Params'] = array(
            'Modulus'       => $details['rsa']['n'],
            'Exponent'      => $details['rsa']['e'],
        );

        if ($this->_publicOnly === FALSE)
        {
            $this->_properties['Params']['P'] = $details['rsa']['p'];
            $this->_properties['Params']['Q'] = $details['rsa']['q'];
            $this->_properties['Params']['D'] = $details['rsa']['d'];
            $this->_properties['Params']['DP'] = $details['rsa']['dmp1'];
            $this->_properties['Params']['DQ'] = $details['rsa']['dmq1'];
            $this->_properties['Params']['InverseQ'] = $details['rsa']['iqmp'];
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Cryptography\AsymmetricAlgorithm::ToXMLString()
     */
    public function ToXMLString($IncludePrivateParamerters = TRUE)
    {
        $xml = new \DOMDocument('1.0', 'UTF-8');
        $root = $xml->createElement('RSAKeyValue');

        if ($IncludePrivateParamerters === FALSE || $this->_publicOnly === TRUE)
        {
            $root->appendChild($xml->createElement('Modulus', $this->_properties['Params']['Modulus']));
            $root->appendChild($xml->createElement('Exponent', $this->_properties['Params']['Exponent']));
        }
        else
        {
            if ($this->_publicOnly === TRUE)
                throw new \Exception('This is a public key, private data cannot be exported');

            foreach ($this->_properties['Params'] as $param => $value)
                $root->appendChild($xml->createElement($param, $value));
        }

        $xml->appendChild($root);

        return $xml->saveXML();
    }

    /**
     * Encrypts the input data using the public key.
     * @param string $Data
     * @param boolean $RawOutput
     * @throws \Exception
     * @return string
     */
    public function Encrypt($Data, $RawOutput = TRUE)
    {
        if (!openssl_public_encrypt($Data, $cipherText, sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", base64_encode($this->PublicKey))));
            throw new \Exception('An error occured while encrypting data');

        return $RawOutput === TRUE ? $cipherText : base64_encode($cipherText);
    }

    /**
     * Decrypts the input data using the private key.
     * @param string $Data
     * @param boolean $RawInput
     * @throws \Exception
     * @return string
     */
    public function Decrypt($Data, $RawInput = TRUE)
    {
        if ($this->_publicOnly === TRUE)
            throw new \Exception('This is a public key, data cannot be decrypted !');

        if (!openssl_private_decrypt($RawInput === TRUE ? $Data : base64_decode($Data), $clearText, $this->_resource))
            throw new \Exception('An error occured while decrypting data');

        return $clearText;
    }
}
