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
 * @brief Handles an error message while enumerating provider types 
 *        (end of the types list is not an error)
 */
void OnEnumFailure()
{
    if (const auto error = GetLastError();
        error != ERROR_NO_MORE_ITEMS && error != ERROR_SUCCESS)
    {
        cas::error::Throw(error);
    }
}


int wmain()
{
    try
    {
        //
        // Set Windows-1251 codepage
        //

        USE_CODEPAGE(cas::utils::kWin1251);

        for (DWORD index = 0; /* Intentionally empty */; ++index)
        {
            DWORD provider_type = 0;
            DWORD type_name_len = 0;

            //
            // Let's get provider type's name length
            //

            if (!CryptEnumProviderTypes(index, nullptr, 0, &provider_type, nullptr, &type_name_len))
            {
                OnEnumFailure();
                break;
            }

            //
            // And now the name itself
            //

            std::wstring type_name(type_name_len, 0);
            if (!CryptEnumProviderTypes(index, nullptr, 0, &provider_type, type_name.data(), &type_name_len))
            {
                OnEnumFailure();
                break;
            }

            //
            // Well, here I need just to print the type in a pretty way
            //

            std::wcout << std::format(LR"(Provider type: {:4} "{}")", provider_type, type_name) << L'\n';
        }

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
