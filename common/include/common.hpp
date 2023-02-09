/**
 * @file common.hpp
 * @brief Набор общих функций и прочего свспомогательного счастья 
 *        для лабораторных по использованию Crypto API
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
 * @brief Получает текст сообщения об ошибке по ее коду.
 */
std::wstring ErrorMessage(DWORD error_code) noexcept;

}  // namespace cas
