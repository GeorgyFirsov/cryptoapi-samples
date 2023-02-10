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
// Boost headers
//

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/any.hpp>


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

static constexpr auto kOptionsHeader       = "Allowed options";
static constexpr auto kHelp                = "help";
static constexpr auto kHelpDefinition      = "help,h";
static constexpr auto kHelpDescription     = "display help message";
static constexpr auto kProvider            = "provider";
static constexpr auto kProviderDefinition  = "provider,p";
static constexpr auto kProviderDescription = "provider to create and delete container for";
static constexpr auto kType                = "type";
static constexpr auto kTypeDefinition      = "type,t";
static constexpr auto kTypeDescription     = "type of the provider";


int wmain(int argc, wchar_t** argv)
{
    try
    {
        //
        // Set Windows-1251 codepage
        //

        USE_CODEPAGE(cas::kWin1251);

        //
        // Parse options
        //

        po::options_description options(kOptionsHeader);

        // clang-format off
        options.add_options()
            (kHelpDefinition, kHelpDescription)
            (kProviderDefinition, po::wvalue<std::wstring>()->required(), kProviderDescription)
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
        // Extract parameters
        //

        const auto provider_name = boost::any_cast<std::wstring>(variables[kProvider].value());
        const auto provider_type = boost::any_cast<DWORD>(variables[kType].value());

        std::wcout << std::format(LR"(Enumerating parameters of provider "{}" of type {})",
                          provider_name, provider_type)
                   << std::endl;

        //
        // Open requested provider (container can be defaulted here)
        //

        cas::Provider provider(provider_name, provider_type);

        //
        // TODO: enumerate parameters
        //

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
