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

static constexpr auto kOptionsHeader        = "Allowed options";
static constexpr auto kHelp                 = "help";
static constexpr auto kHelpDefinition       = "help,h";
static constexpr auto kHelpDescription      = "display help message";
static constexpr auto kProvider             = "provider";
static constexpr auto kProviderDefinition   = "provider,p";
static constexpr auto kProviderDescription  = "provider to create and delete container for";
static constexpr auto kType                 = "type";
static constexpr auto kTypeDefinition       = "type,t";
static constexpr auto kTypeDescription      = "type of the provider";
static constexpr auto kContainer            = "container";
static constexpr auto kContainerDefinition  = "container,c";
static constexpr auto kContainerDescription = "container name";


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
            (kProviderDefinition, po::wvalue<std::wstring>()->required(), kProviderDescription)
            (kTypeDefinition, po::wvalue<DWORD>()->required(), kTypeDescription)
            (kContainerDefinition, po::wvalue<std::wstring>()->required(), kContainerDescription)
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

        const auto provider_name  = boost::any_cast<std::wstring>(variables[kProvider].value());
        const auto provider_type  = boost::any_cast<DWORD>(variables[kType].value());
        const auto container_name = boost::any_cast<std::wstring>(variables[kContainer].value());

        std::wcout << std::format(LR"(Using provider "{}" of type {} to create container with name "{}")",
                          provider_name, provider_type, container_name)
                   << std::endl;

        {
            //
            // Create key container by using CRYPT_NEWKEYSET flag. Context will be released
            // at the scope exit.
            //

            cas::crypto::Provider provider(container_name, provider_name, provider_type, CRYPT_NEWKEYSET);

            std::wcout << L"Container was created successfully\n";
        }

        {
            //
            // And here we delete container, that was created earlier
            //

            cas::crypto::Provider provider(container_name, provider_name, provider_type, CRYPT_DELETEKEYSET);

            std::wcout << L"Container was removed successfully\n";
        }

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
