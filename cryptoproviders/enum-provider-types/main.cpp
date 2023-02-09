//
// Windows headers
//

#include <windows.h>
#include <wincrypt.h>


//
// STL headers
//

#include <iostream>
#include <string>
#include <format>


//
// Own headers
//

#include "common.hpp"


/**
 * @brief ������� ���������� �� ������, ������������ ��� ������������
 *        ����� ����������� (����� �������� ������� �� ���������)
 */
void TraceEnumFailure()
{
    if (const auto error = GetLastError();
        error != ERROR_NO_MORE_ITEMS && error != ERROR_SUCCESS)
    {
        std::wcerr << cas::ErrorMessage(error) << std::endl;
    }
}


int wmain()
{
    try
    {
        for (DWORD index = 0; /* ��� ������ ��� ��������� */; ++index)
        {
            DWORD provider_type     = 0;
            DWORD provider_name_len = 0;

            //
            // ������� ����� ������ ��� ��� ����������
            //

            if (!CryptEnumProviderTypes(index, nullptr, 0, &provider_type, nullptr, &provider_name_len))
            {
                TraceEnumFailure();
                break;
            }

            //
            // �� � ������ ������ � ���� ��� ����������
            //

            std::wstring provider_name(provider_name_len, 0);
            if (!CryptEnumProviderTypes(index, nullptr, 0, &provider_type, provider_name.data(), &provider_name_len))
            {
                TraceEnumFailure();
                break;
            }

            //
            // �� � �������� ������ ����������� ��� ���������� ����
            //

            std::wcout << std::format(L"Provider type: {:2} ({})\n", provider_type, provider_name);
        }
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;
    }
}
