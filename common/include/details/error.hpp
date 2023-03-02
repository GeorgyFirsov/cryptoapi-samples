/**
 * @file error.hpp
 * @brief Error handling functions and related stuff
 */

#pragma once

//
// Windows headers
//

#include "windows.hpp"


//
// STL headers
//

#include <format>
#include <string>
#include <stdexcept>
#include <source_location>


namespace cas::error {
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
 * @brief Throws a std::runtime_error instance with error code description.
 * * 
 * @param error_code Error code to provide description of
 */
[[noreturn]] inline void Throw(DWORD error_code, std::source_location loc = std::source_location::current())
{
    const auto error_message = std::format("Error 0x{:08X} in '{}' at '{}:{}'.\nDescription: {}",
        error_code, loc.function_name(), loc.file_name(), loc.line(), ErrorMessage<std::string>(error_code));

    throw std::runtime_error(error_message);
}


/**
 * @brief Throws a std::runtime_error instance with last error code description.
 */
[[noreturn]] inline void ThrowLast(std::source_location loc = std::source_location::current())
{
    Throw(GetLastError(), loc);
}

}  // namespace cas::error
