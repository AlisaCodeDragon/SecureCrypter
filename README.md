# Secure Crypter

Secure Crypter is a reliable, fast, and effective text encryption library designed to protect your sensitive data. Developed using industry-standard cryptographic techniques, this encryption solution provides strong security with AES-256 CBC encryption algorithm and HMAC data integrity verification method. Easy to use, Secure Crypter is initialized with a secure key, allowing users to perform data encryption and decryption quickly and securely. Equipped with advanced encryption technology, Secure Crypter is a reliable solution for protecting your sensitive data. By choosing Secure Crypter for your data security, you can store your information with confidence.

## Languages
- **CPP:**
- **C#:** `Soon`
- **PHP:**

## Versions
- **CPP:** `std:c++20`
- **PHP:** `8.3.4`
- **OpenSSL:** `3.0.13`

## Usage 

Here is a simple example demonstrating how to use Secure Crypter:
- [Random 256-bit Security Key Generator](https://acte.ltd/utils/randomkeygen)


> C++
```cpp
#include <iostream>
#include "SecureCrypter.hpp"

int main(int argc, char* argv[]) {
    // Initialize SecureCrypter with a security key
    std::u8string securityKey = u8"your_secure_key_here";
    SecureCrypter secureCrypter(securityKey);

    // Plaintext to be encrypted
    std::u8string plainText = u8"Hello World!";

    // Encrypt the plaintext
    std::u8string encryptedText = secureCrypter.encryptData(plainText);

    // Decrypt the encrypted text
    std::u8string decryptedText = secureCrypter.decryptData(encryptedText);

    // Display results
    std::cout << "Plaintext: " << std::string(plainText.begin(), plainText.end()) << std::endl;
    std::cout << "Encrypted: " << std::string(encryptedText.begin(), encryptedText.end()) << std::endl;
    std::cout << "Decrypted: " << std::string(decryptedText.begin(), decryptedText.end()) << std::endl;

    return 0;
}
```

> PHP
```php
<?php
require_once 'SecureCrypter.php';

// Initialize SecureCrypter with a security key
$securityKey = "your_secure_key_here";
$secureCrypter = new SecureCrypter($securityKey);

// Plaintext to be encrypted
$plainText = "Hello World!";

// Encrypt the plaintext
$encryptedText = $secureCrypter->encryptData($plainText);

// Decrypt the encrypted text
$decryptedText = $secureCrypter->decryptData($encryptedText);

// Display results
echo "Plaintext: " . $plainText . "\n";
echo "Encrypted: " . $encryptedText . "\n";
echo "Decrypted: " . $decryptedText . "\n";
?>
```

## Acknowledgments
- [OpenSSL](https://github.com/openssl/openssl) (TLS/SSL and crypto library)

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](https://github.com/furkankadirguzeloglu/SecureCrypter/blob/main/LICENSE) file for details.
