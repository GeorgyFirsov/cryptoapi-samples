/**
 * @file crypto.hpp
 * @brief CryptoAPI helpers implementation
 */

//
// STL headers
//

#include <algorithm>
#include <iterator>


//
// Library headers
//

#include "details/crypto.hpp"
#include "details/utils.hpp"
#include "details/error.hpp"


namespace cas::crypto {

Provider::Provider(LPCWSTR container_name, LPCWSTR provider_name, DWORD provider_type, DWORD flags /* = 0 */)
    : provider_(0)
{
    if (!CryptAcquireContext(&provider_, container_name, provider_name, provider_type, flags))
    {
        error::ThrowLast();
    }

    if (FLAG_ON(CRYPT_DELETEKEYSET, flags))
    {
        //
        // If one requests a container to be deleted,
        // CryptReleaseContext need not to be called
        //

        provider_ = 0;
    }
}


Provider::Provider(const std::wstring& container_name, const std::wstring& provider_name, DWORD provider_type, DWORD flags /* = 0 */)
    : Provider(container_name.c_str(), provider_name.c_str(), provider_type, flags)
{ }


Provider::Provider(const std::wstring& provider_name, DWORD provider_type, DWORD flags /* = 0 */)
    : Provider(nullptr, provider_name.c_str(), provider_type, flags)
{ }


Provider::Provider(DWORD provider_type, DWORD flags /* = 0 */)
    : Provider(nullptr, nullptr, provider_type, flags)
{ }


Provider::~Provider()
{
    Clear();
}


void Provider::Clear() noexcept
{
    if (provider_)
    {
        CryptReleaseContext(std::exchange(provider_, 0), 0);
    }
}


Key::Key(HCRYPTPROV provider, ALG_ID algorithm, DWORD flags /* = 0 */)
    : key_(0)
{
    if (!CryptGenKey(provider, algorithm, flags, &key_))
    {
        error::ThrowLast();
    }
}


Key::Key(HCRYPTPROV provider, const sec_vector<unsigned char>& buffer, HCRYPTKEY public_key /* = 0 */, DWORD flags /* = 0 */)
    : key_(0)
{
    if (!CryptImportKey(provider, buffer.data(), static_cast<DWORD>(buffer.size()), public_key, flags, &key_))
    {
        error::ThrowLast();
    }
}


Key::~Key()
{
    Clear();
}


Key::Key(const Key& other)
    : key_(0)
{
    if (!CryptDuplicateKey(other.key_, nullptr, 0, &key_))
    {
        error::ThrowLast();
    }
}


Key& Key::operator=(const Key& other)
{
    if (this == &other)
    {
        return *this;
    }

    if (!CryptDuplicateKey(other.key_, nullptr, 0, &key_))
    {
        error::ThrowLast();
    }

    return *this;
}


void Key::Clear() noexcept
{
    if (key_)
    {
        CryptDestroyKey(std::exchange(key_, 0));
    }
}


sec_vector<unsigned char> Key::Export(DWORD type)
{
    return Export(0, type);
}


sec_vector<unsigned char> Key::Export(HCRYPTKEY export_key, DWORD type)
{
    DWORD buffer_size = 0;
    if (!CryptExportKey(key_, export_key, type, 0, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> buffer(buffer_size, 0);
    if (!CryptExportKey(key_, export_key, type, 0, buffer.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return buffer;
}


void Key::SetParameter(DWORD parameter, const void* data, DWORD flags /* = 0 */)
{
    if (!CryptSetKeyParam(key_, parameter, static_cast<const BYTE*>(data), flags))
    {
        error::ThrowLast();
    }
}


sec_vector<unsigned char> Key::GetParameter(DWORD parameter, DWORD flags /* = 0 */)
{
    DWORD buffer_size = 0;
    if (!CryptGetKeyParam(key_, parameter, nullptr, &buffer_size, flags))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> buffer(buffer_size, 0);
    if (!CryptGetKeyParam(key_, parameter, buffer.data(), &buffer_size, flags))
    {
        error::ThrowLast();
    }

    return buffer;
}


Hash::Hash(HCRYPTPROV provider, ALG_ID algid, HCRYPTKEY key /* = 0 */, DWORD flags /* = 0 */)
    : hash_(0)
{
    if (!CryptCreateHash(provider, algid, key, flags, &hash_))
    {
        error::ThrowLast();
    }
}


Hash::~Hash()
{
    Clear();
}


void Hash::Clear() noexcept
{
    if (hash_)
    {
        CryptDestroyHash(std::exchange(hash_, 0));
    }
}


CertStore::CertStore(LPCSTR store_provider, DWORD encoding_type, DWORD flags, const void* parameter)
    : store_(CertOpenStore(store_provider, encoding_type, 0, flags, parameter))
{
    if (!store_ && CERT_STORE_DELETE_FLAG != (CERT_STORE_DELETE_FLAG & flags))
    {
        error::ThrowLast();
    }
}


CertStore::~CertStore()
{
    Clear();
}


void CertStore::Clear() noexcept
{
    if (store_)
    {
        CertCloseStore(std::exchange(store_, nullptr), 0);
    }
}


Certificate::Certificate(PCCERT_CONTEXT cert) noexcept
    : cert_(cert)
{
    if (!cert_)
    {
        error::ThrowLast();
    }
}


/* static */ Certificate Certificate::CreateSelfSigned(HCRYPTPROV provider, PCERT_NAME_BLOB issuer, DWORD flags /* = 0 */,
    PCRYPT_KEY_PROV_INFO key_provider_info /* = nullptr */, PCRYPT_ALGORITHM_IDENTIFIER signature_algorithm /* = nullptr */,
    PSYSTEMTIME start_time /* = nullptr */, PSYSTEMTIME end_time /* = nullptr */, PCERT_EXTENSIONS extensions /* = nullptr */)
{
    return CertCreateSelfSignCertificate(provider, issuer, flags, key_provider_info, signature_algorithm,
        start_time, end_time, extensions);
}


/* static */ Certificate Certificate::FindInStore(HCERTSTORE store, DWORD encoding_type, DWORD flags, DWORD find_type,
    const void* find_parameter, PCCERT_CONTEXT previous /* = nullptr */)
{
    return CertFindCertificateInStore(store, encoding_type, flags, find_type, find_parameter, previous);
}


Certificate::~Certificate()
{
    Clear();
}


void Certificate::Clear() noexcept
{
    if (cert_)
    {
        CertFreeCertificateContext(std::exchange(cert_, nullptr));
    }
}


sec_vector<unsigned char> Certificate::GetProperty(DWORD property) const
{
    DWORD buffer_size = 0;
    if (!CertGetCertificateContextProperty(cert_, property, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> result(buffer_size, 0);
    if (!CertGetCertificateContextProperty(cert_, property, result.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return result;
}


PublicKeyInfo::PublicKeyInfo(HCRYPTPROV provider, DWORD key_specification,
    DWORD encoding_type /* = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING */)
    : buffer_()
{
    DWORD buffer_size = 0;
    if (!CryptExportPublicKeyInfo(provider, key_specification, encoding_type, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    buffer_.resize(buffer_size);
    if (!CryptExportPublicKeyInfo(provider, key_specification, encoding_type,
            reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(buffer_.data()), &buffer_size))
    {
        error::ThrowLast();
    }
}


encryption_result_t EncryptCbcAndSign(HCRYPTPROV provider, Key key, const sec_vector<unsigned char>& plaintext)
{
    //
    // Query some parameters
    //

    const auto block_len_buffer = key.GetParameter(KP_BLOCKLEN);
    const auto block_len        = *reinterpret_cast<const DWORD*>(block_len_buffer.data()) / 8;
    const auto ciphertext_len   = (plaintext.size() + block_len - 1) & ~(block_len - 1);
    const auto full_buffer_len  = block_len + ciphertext_len;

    sec_vector<unsigned char> result(block_len, 0);
    result.reserve(full_buffer_len);

    //
    // Generate IV and put directly to the output buffer
    //

    if (!CryptGenRandom(provider, block_len, result.data()))
    {
        error::ThrowLast();
    }

    //
    // Set encryption parameters
    //

    DWORD mode    = CRYPT_MODE_CBC;
    DWORD padding = PKCS5_PADDING;

    key.SetParameter(KP_MODE, &mode);
    key.SetParameter(KP_PADDING, &padding);
    key.SetParameter(KP_IV, result.data());

    //
    // Copy plaintext to output buffer right after IV
    //

    std::ranges::copy(plaintext, std::back_inserter(result));
    result.resize(full_buffer_len, 0);

    //
    // Create hash object, that will be signed afterwards and encrypt data
    //

    Hash hash(provider, CALG_SHA_256);
    auto data_length = static_cast<DWORD>(plaintext.size());

    if (!CryptEncrypt(key, hash, TRUE, 0, result.data() + block_len, &data_length, ciphertext_len))
    {
        error::ThrowLast();
    }

    //
    // Now let's sign the hash and return result
    //

    return std::make_pair(result, SignHash(hash, AT_SIGNATURE));
}


sec_vector<unsigned char> DecryptCbcAndVerify(HCRYPTPROV provider, Key encryption_key,
    Key verification_key, const encryption_result_t& signed_ciphertext)
{
    //
    // Query some parameters
    //

    const auto block_len_buffer = encryption_key.GetParameter(KP_BLOCKLEN);
    const auto block_len        = *reinterpret_cast<const DWORD*>(block_len_buffer.data()) / 8;

    //
    // Split ciphertext and its signature
    //

    const auto& [ciphertext, signature] = signed_ciphertext;

    //
    // Set decryption parameters
    //

    DWORD mode    = CRYPT_MODE_CBC;
    DWORD padding = PKCS5_PADDING;

    encryption_key.SetParameter(KP_MODE, &mode);
    encryption_key.SetParameter(KP_PADDING, &padding);
    encryption_key.SetParameter(KP_IV, ciphertext.data());

    //
    // Copy ciphertext to output buffer
    //

    sec_vector<unsigned char> result(std::next(ciphertext.cbegin(), block_len), ciphertext.cend());

    //
    // Create hash and decrypt message
    //

    Hash hash(provider, CALG_SHA_256);
    auto data_length = static_cast<DWORD>(ciphertext.size() - block_len);

    if (!CryptDecrypt(encryption_key, hash, TRUE, 0, result.data(), &data_length))
    {
        error::ThrowLast();
    }

    result.resize(data_length);

    //
    // Let's verify signature
    //

    VerifySignature(hash, verification_key, signature);

    return result;
}


sec_vector<unsigned char> SignHash(HCRYPTHASH hash, DWORD key_spec /* = AT_SIGNATURE */)
{
    DWORD signature_len = 0;
    if (!CryptSignHash(hash, AT_SIGNATURE, nullptr, 0, nullptr, &signature_len))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> signature(signature_len, 0);
    if (!CryptSignHash(hash, AT_SIGNATURE, nullptr, 0, signature.data(), &signature_len))
    {
        error::ThrowLast();
    }

    return signature;
}


void VerifySignature(HCRYPTHASH hash, HCRYPTKEY verification_key, const sec_vector<unsigned char>& signature)
{
    if (!CryptVerifySignature(hash, signature.data(), signature.size(), verification_key, nullptr, 0))
    {
        error::ThrowLast();
    }
}


sec_vector<unsigned char> EncodeObject(DWORD encoding_type, LPCSTR struct_type, const void* struct_data)
{
    DWORD buffer_size = 0;
    if (!CryptEncodeObject(encoding_type, struct_type, struct_data, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> result(buffer_size, 0);
    if (!CryptEncodeObject(encoding_type, struct_type, struct_data, result.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return result;
}


sec_vector<unsigned char> SignAndEncodeCertificate(HCRYPTPROV provider, DWORD key_specification, DWORD encoding_type,
    LPCSTR struct_type, const void* struct_data, PCRYPT_ALGORITHM_IDENTIFIER signature_algorithm)
{
    DWORD buffer_size = 0;
    if (!CryptSignAndEncodeCertificate(provider, key_specification, encoding_type, struct_type,
            struct_data, signature_algorithm, nullptr, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> result(buffer_size, 0);
    if (!CryptSignAndEncodeCertificate(provider, key_specification, encoding_type, struct_type,
            struct_data, signature_algorithm, nullptr, result.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return result;
}

}  // namespace cas::crypto
