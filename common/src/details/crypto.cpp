/**
 * @file crypto.hpp
 * @brief CryptoAPI helpers implementation
 */


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

}  // namespace cas::crypto
