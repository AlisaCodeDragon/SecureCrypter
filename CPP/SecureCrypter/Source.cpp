#include "iostream"
#include "SecureCrypter.hpp"

int main(int argc, char* argv[]) {
    std::u8string securityKey = u8"your_secure_key_here";
    SecureCrypter secureCrypter(securityKey);

    std::u8string plainText = u8"Hello World!";
    std::u8string encryptedText = secureCrypter.encryptData(plainText);
    std::u8string decryptedText = secureCrypter.decryptData(encryptedText);

    std::cout << "Plaintext: " << std::string(plainText.begin(), plainText.end()) << std::endl;
    std::cout << "Encrypted: " << std::string(encryptedText.begin(), encryptedText.end()) << std::endl;
    std::cout << "Decrypted: " << std::string(decryptedText.begin(), decryptedText.end()) << std::endl;

    return 0;
}