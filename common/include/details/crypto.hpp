/**
 * @file crypto.hpp
 * @brief CryptoAPI helpers
 */

#pragma once

//
// Windows headers
//

#include "details/windows.hpp"


//
// STL headers
//

#include <string>


namespace cas::crypto {

/**
 * @brief Wrapper over HCRYPTPROV. Frees handle at a scope exit.
 */
class Provider final
{
    Provider(const Provider&)            = delete;
    Provider& operator=(const Provider&) = delete;

    Provider(Provider&&)            = delete;
    Provider& operator=(Provider&&) = delete;

public:
    /**
     * @brief Constructor, that just forwards its arguments into CryptAcquireContext.
     */
    explicit Provider(LPCWSTR container_name, LPCWSTR provider_name, DWORD provider_type, DWORD flags = 0);

    /**
     * @brief The same constructor as the previous one, but accepts STL strings 
     * instead of C-style ones.
     */
    explicit Provider(const std::wstring& container_name, const std::wstring& provider_name, DWORD provider_type, DWORD flags = 0);

    /**
     * @brief The same as the previous one, but sets container name to nullptr.
     */
    explicit Provider(const std::wstring& provider_name, DWORD provider_type, DWORD flags = 0);

    /**
     * @brief Destructor. Just calls cas::Provider::Clear.
     */
    ~Provider();

    /**
     * @brief Frees a wrapped provider.
     */
    void Clear() noexcept;

    /**
     * @brief Get the internal provider handle.
     */
    operator HCRYPTPROV() const noexcept { return provider_; }

private:
    // Internal provider handle
    HCRYPTPROV provider_;
};

}  // namespace cas::crypto
