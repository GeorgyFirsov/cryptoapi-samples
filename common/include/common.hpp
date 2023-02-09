/**
 * @file common.hpp
 * @brief ����� ����� ������� � ������� ����������������� ������� 
 *        ��� ������������ �� ������������� Crypto API
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
 * @brief �������� ����� ��������� �� ������ �� �� ����.
 */
std::wstring ErrorMessage(DWORD error_code) noexcept;

}  // namespace cas
