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
 * @brief Print an error message while enumerating provider types 
 *        (end of the types list is not an error)
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
        for (DWORD index = 0; /* Intentionally empty */; ++index)
        {
            DWORD provider_type     = 0;
            DWORD provider_name_len = 0;

            //
            // Let's get provider type's name length
            //

            if (!CryptEnumProviderTypes(index, nullptr, 0, &provider_type, nullptr, &provider_name_len))
            {
                TraceEnumFailure();
                break;
            }

            //
            // And now the name itself
            //

            std::wstring provider_name(provider_name_len, 0);
            if (!CryptEnumProviderTypes(index, nullptr, 0, &provider_type, provider_name.data(), &provider_name_len))
            {
                TraceEnumFailure();
                break;
            }

            //
            // Well, here I need just to print the type in a pretty way
            //

            std::wcout << std::format(L"Provider type: {:4} ({})\n", provider_type, provider_name);
        }

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
