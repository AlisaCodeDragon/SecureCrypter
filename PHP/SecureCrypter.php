<?php
class SecureCrypter {
    private $securityKey;
    
    public function __construct($securityKey) {
        if (!extension_loaded('openssl')) {
            throw new Exception("OpenSSL extension is not loaded. OpenSSL extension is required for these functions to work.");
        }
        
        if (strlen($securityKey) !== 32) {
            throw new Exception("Key length must be 32 bytes (256 bits) for AES-256.");
        }

        $this->securityKey = $securityKey;
    }

    private function encryptCustomStrrev($data){
        $length = strlen($data);
        if ($length === 0) {
            return "";
        }
        $dividerIndex = ceil($length / 2);
        if ($length % 2 !== 0) {
            $dividerIndex++;
        }   
        $firstPart = substr($data, 0, $dividerIndex);
        $secondPart = substr($data, $dividerIndex);
        $reversedFirstPart = strrev($firstPart);
        $reversedSecondPart = strrev($secondPart);
        $resultData = $reversedSecondPart . $reversedFirstPart;
        return $resultData;
    }

    private function decryptcustomStrrevc($data){
        $length = strlen($data);
        $dividerIndex = floor($length / 2);
        if ($length % 2 !== 0) {
            $dividerIndex++;
        }   
        $reversedFirstPart = substr($data, 0, $dividerIndex);
        $reversedSecondPart = substr($data, $dividerIndex);
        $firstPart = strrev($reversedFirstPart);
        $secondPart = strrev($reversedSecondPart);
        $originalData = $secondPart . $firstPart;
        return $originalData;
    }

    public function encryptData($data) {
        $data = $this->encryptCustomStrrev($data);
        $iv = openssl_random_pseudo_bytes(16);
        if ($iv === false) {
            throw new Exception("IV generation failed.");
        }
        
        $encryptedData = openssl_encrypt($data, "aes-256-cbc", $this->securityKey, OPENSSL_RAW_DATA, $iv);
        if ($encryptedData === false) {
            throw new Exception("Encryption failed.");
        }

        $mac = hash_hmac('sha256', $encryptedData, $this->securityKey, true);
        if ($mac === false) {
            throw new Exception("HMAC generation failed.");
        }

        return $this->encryptCustomStrrev(base64_encode($iv . $mac . $encryptedData));
    }    

    public function decryptData($data) {
        $decodedData = base64_decode($this->decryptcustomStrrevc($data));
        if ($decodedData === false || strlen($decodedData) < 48) {
            throw new Exception("Invalid data format.");
        }
        
        $iv = substr($decodedData, 0, 16);
        $mac = substr($decodedData, 16, 32);
        $encryptedData = substr($decodedData, 48);
        
        $calculatedMac = hash_hmac('sha256', $encryptedData, $this->securityKey, true);
        if ($calculatedMac === false || !hash_equals($mac, $calculatedMac)) {
            throw new Exception("HMAC validation failed.");
        }
        
        $decryptedData = openssl_decrypt($encryptedData, "aes-256-cbc", $this->securityKey, OPENSSL_RAW_DATA, $iv);
        if ($decryptedData === false) {
            throw new Exception("Decryption failed.");
        }
        
        return $this->decryptcustomStrrevc($decryptedData);
    }    
}