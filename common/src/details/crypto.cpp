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

}  // namespace cas::crypto