//
// Windows headers
//

#include "windows.hpp"
#include <wincrypt.h>


//
// STL headers
//

#include <iostream>
#include <string>
#include <format>


//
// Boost headers
//

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>


//
// Own headers
//

#include "common.hpp"


//
// Just for simplicity
//

namespace po = boost::program_options;


//
// Some constants
//

static constexpr auto kOptionsHeader   = "Allowed options";
static constexpr auto kHelp            = "help";
static constexpr auto kHelpDefinition  = "help,h";
static constexpr auto kHelpDescription = "display help message";
static constexpr auto kType            = "type";
static constexpr auto kTypeDefinition  = "type,t";
static constexpr auto kTypeDescription = "type which to list providers of";


/**
 * @brief Handes an error message while enumerating provider types
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


int wmain(int argc, wchar_t** argv)
{
    try
    {
        //
        // Set Windows-1251 codepage
        //

        USE_CODEPAGE(cas::utils::kWin1251);

        //
        // Parse options
        //

        po::options_description options(kOptionsHeader);

        // clang-format off
        options.add_options()
            (kHelpDefinition, kHelpDescription)
            (kTypeDefinition, po::wvalue<DWORD>()->required(), kTypeDescription)
            ;
        // clang-format on

        po::variables_map variables;
        po::store(po::parse_command_line(argc, argv, options), variables);

        if (!variables[kHelp].empty())
        {
            std::cout << options << std::endl;
            return -1;
        }

        po::notify(variables);

        //
        // Get provider type and list all providers of this type
        //

        const auto requested_type = variables[kType].as<DWORD>();

        for (DWORD index = 0; /* Intentionally empty */; ++index)
        {
            DWORD provider_type     = 0;
            DWORD provider_name_len = 0;

            //
            // Let's get provider type's name length
            //

            if (!CryptEnumProviders(index, nullptr, 0, &provider_type, nullptr, &provider_name_len))
            {
                OnEnumFailure();
                break;
            }

            if (provider_type != requested_type)
            {
                //
                // Wrong type, skipping...
                //

                continue;
            }

            //
            // And now the name itself
            //

            std::wstring provider_name(provider_name_len, 0);
            if (!CryptEnumProviders(index, nullptr, 0, &provider_type, provider_name.data(), &provider_name_len))
            {
                OnEnumFailure();
                break;
            }

            //
            // Well, here I need just to print the type in a pretty way
            //

            std::wcout << std::format(LR"(Provider: "{}" (of type {}))", provider_name, provider_type) << L'\n';
        }

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
