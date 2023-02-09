/**
 * @file common.hpp
 * @brief Set of helpers for Crypto API labs
 */
#pragma once

//
// Windows headers
//

#include <windows.h>


//
// STL headers
//

#include <string>


namespace cas {

/**
 * @brief Retreives an error message by its code
 */
std::wstring ErrorMessage(DWORD error_code) noexcept;

}  // namespace cas
