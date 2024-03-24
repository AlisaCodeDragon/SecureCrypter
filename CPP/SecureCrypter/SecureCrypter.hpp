#include <string>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

class SecureCrypter {
private:
    std::u8string securityKey;
    std::u8string encryptCustomStrrev(const std::u8string data) {
        std::u8string resultData;
        size_t length = data.length();
        if (length == 0) {
            return u8"";
        }
        size_t dividerIndex = static_cast<size_t>(std::floor(static_cast<double>(length) / 2.0));
        if (length % 2 != 0) {
            dividerIndex++;
        }
        std::u8string firstPart = data.substr(0, dividerIndex);
        std::u8string secondPart = data.substr(dividerIndex);
        std::reverse(firstPart.begin(), firstPart.end());
        std::reverse(secondPart.begin(), secondPart.end());
        resultData = secondPart + firstPart;
        return resultData;
    }

    std::u8string decryptCustomStrrevc(const std::u8string data) {
        std::u8string originalData;
        size_t length = data.length();
        size_t dividerIndex = static_cast<size_t>(std::floor(static_cast<double>(length) / 2.0));
        if (length % 2 != 0) {
            dividerIndex++;
        }
        std::u8string reversedFirstPart = data.substr(0, dividerIndex);
        std::u8string reversedSecondPart = data.substr(dividerIndex);
        std::reverse(reversedFirstPart.begin(), reversedFirstPart.end());
        std::reverse(reversedSecondPart.begin(), reversedSecondPart.end());
        originalData = reversedSecondPart + reversedFirstPart;
        return originalData;
    }

    std::u8string base64_encode(const std::u8string input) {
        BIO* bio, * b64;
        BUF_MEM* bufferPtr;
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, input.c_str(), input.length());
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);
        return std::u8string(reinterpret_cast<const char8_t*>(bufferPtr->data), bufferPtr->length);
    }

    std::u8string base64_decode(const std::u8string input) {
        BIO* bio, * b64;
        char* buffer = new char[input.size()];
        memset(buffer, 0, input.size());
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(input.c_str(), input.size());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_set_mem_eof_return(bio, 0);
        int decodedLength = BIO_read(bio, buffer, input.size());
        BIO_free_all(bio);
        return std::u8string(reinterpret_cast<const char8_t*>(buffer), decodedLength);
    }
public:
    SecureCrypter(const std::u8string securityKey) : securityKey(securityKey) {
        if (securityKey.size() != 32) {
            throw std::invalid_argument("Key length must be 32 bytes (256 bits) for AES-256.");
        }
    }

    std::u8string encryptData(std::u8string data) {
        data = encryptCustomStrrev(data);
        std::u8string iv(16, 0);
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&iv[0]), 16) != 1) {
            throw std::runtime_error("IV generation failed.");
        }

        EVP_CIPHER_CTX* ctx;
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            throw std::runtime_error("Unable to create context.");
        }

        if (EVP_EncryptInit_ex(
            ctx, EVP_aes_256_cbc(), NULL,
            reinterpret_cast<const unsigned char*>(securityKey.c_str()),
            reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed.");
        }

        std::u8string encryptedData(data.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), 0);
        int encryptedLen;
        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&encryptedData[0]), &encryptedLen, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed.");
        }

        int finalLen;
        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&encryptedData[encryptedLen]), &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed.");
        }

        EVP_CIPHER_CTX_free(ctx);
        encryptedData.resize(encryptedLen + finalLen);
        std::u8string mac(EVP_MAX_MD_SIZE, 0);
        unsigned int macLen;
        if (HMAC(EVP_sha256(), securityKey.c_str(), securityKey.length(),
            reinterpret_cast<const unsigned char*>(encryptedData.c_str()),
            encryptedData.length(), reinterpret_cast<unsigned char*>(&mac[0]),
            &macLen) == NULL) {
            throw std::runtime_error("HMAC generation failed.");
        }
        mac.resize(macLen);
        return encryptCustomStrrev(base64_encode(iv + mac + encryptedData));
    }

    std::u8string decryptData(std::u8string data) {
        std::u8string decodedData = base64_decode(decryptCustomStrrevc(data));
        if (decodedData.length() < 48) {
            throw std::runtime_error("Invalid data format.");
        }

        std::u8string iv = decodedData.substr(0, 16);
        std::u8string mac = decodedData.substr(16, 32);
        std::u8string encryptedData = decodedData.substr(48);
        std::u8string calculatedMac(EVP_MAX_MD_SIZE, 0);
        unsigned int macLen;
        if (HMAC(EVP_sha256(), securityKey.c_str(), securityKey.length(), reinterpret_cast<const unsigned char*>(encryptedData.c_str()), encryptedData.length(), reinterpret_cast<unsigned char*>(&calculatedMac[0]), &macLen) == NULL) {
            throw std::runtime_error("HMAC validation failed.");
        }
        calculatedMac.resize(macLen);
        if (mac != calculatedMac) {
            throw std::runtime_error("HMAC validation failed.");
        }

        EVP_CIPHER_CTX* ctx;
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            throw std::runtime_error("Unable to create context.");
        }

        std::u8string decryptedData(encryptedData.length(), 0);
        int decryptedLen;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(securityKey.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed.");
        }

        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&decryptedData[0]), &decryptedLen, reinterpret_cast<const unsigned char*>(encryptedData.c_str()), encryptedData.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed.");
        }

        int finalLen;
        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&decryptedData[decryptedLen]), &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed.");
        }

        EVP_CIPHER_CTX_free(ctx);
        decryptedData.resize(decryptedLen + finalLen);
        return decryptCustomStrrevc(decryptedData);
    }
};