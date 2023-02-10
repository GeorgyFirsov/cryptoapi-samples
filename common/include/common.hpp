/**
 * @file common.hpp
 * @brief Set of helpers for Crypto API labs
 */
#pragma once

//
// Windows headers
//

#include <windows.h>
#include <wincrypt.h>


//
// STL headers
//

#include <string>
#include <utility>


namespace cas {
namespace details {

template<typename String>
struct FormatTraits;

template<>
struct FormatTraits<std::wstring>
{
    using buffer_t = LPWSTR;

    template<typename... Tys>
    static auto Format(Tys&&... args)
    {
        return FormatMessageW(std::forward<Tys>(args)...);
    }
};


template<>
struct FormatTraits<std::string>
{
    using buffer_t = LPSTR;

    template<typename... Tys>
    static auto Format(Tys&&... args)
    {
        return FormatMessageA(std::forward<Tys>(args)...);
    }
};

}  // namespace details

/**
 * @brief Checks if specific flag is set in the bit mask.
 */
#define FLAG_ON(flag, flags) (!!((flags) & (flag)))


/**
 * @brief Sets a codepage for current application's console
 */
#define SET_CODEPAGE(cp) static auto cp_init_ = []() { \
  SetConsoleCP(cp);                                    \
  SetConsoleOutputCP(cp);                              \
  return 0;                                            \
}()


/**
 * @brief Retreives an error message by its code.
 * 
 * @param error_code Code to get description for
 */
template<typename String = std::wstring>
String ErrorMessage(DWORD error_code) noexcept
{
    using traits_t = details::FormatTraits<String>;
    using buffer_t = typename traits_t::buffer_t;

    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;

    buffer_t buffer     = nullptr;
    const DWORD written = traits_t::Format(flags, nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<buffer_t>(&buffer), 0, nullptr);

    String result;

    if (written)
    {
        result.assign(buffer, written);
        LocalFree(buffer);
    }

    return result;
}


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
    explicit Provider(LPCWSTR container_name, LPCWSTR provider_name, DWORD provider_type, DWORD flags = 0);
    explicit Provider(const std::wstring& container_name, const std::wstring& provider_name, DWORD provider_type, DWORD flags = 0);

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

}  // namespace cas
