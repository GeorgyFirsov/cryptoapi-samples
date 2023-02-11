//
// Configuration macros
//

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX


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
#include <functional>


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


/**
 * @brief Type of handler for algorithms enumeration.
 */
using enum_algs_handler_t = std::function<void(const PROV_ENUMALGS_EX&)>;

/**
 * @brief Enumerates all algorithms supported by provider.
 *
 * @param provider Provider to enumerate algorithms for
 * @param handler Functor to invoke for each supported algorithm
 */
void EnumerateAlgorithms(HCRYPTPROV provider, const enum_algs_handler_t& handler)
{
    PROV_ENUMALGS_EX alg = {};
    auto alg_bytes       = reinterpret_cast<BYTE*>(&alg);
    auto size            = static_cast<DWORD>(sizeof(alg));

    if (!CryptGetProvParam(provider, PP_ENUMALGS_EX, alg_bytes, &size, CRYPT_FIRST))
    {
        cas::error::ThrowLast();
    }

    handler(alg);

    while (CryptGetProvParam(provider, PP_ENUMALGS_EX, alg_bytes, &size, CRYPT_NEXT))
    {
        handler(alg);
    }

    if (const auto last_error = GetLastError(); ERROR_NO_MORE_ITEMS != last_error)
    {
        cas::error::Throw(last_error);
    }
}


/**
 * @brief Type of handler for version querying.
 */
using version_handler_t = std::function<void(DWORD, DWORD)>;

/**
 * @brief Obtains a provider's version, parses it and forwards into
 * user-defined callback.
 *
 * @param provider Provider to get version of
 * @param handler Functor to invoke with obtained version
 */
void QueryVersion(HCRYPTPROV provider, const version_handler_t& handler)
{
    DWORD version      = 0;
    auto version_bytes = reinterpret_cast<BYTE*>(&version);
    auto size          = static_cast<DWORD>(sizeof(version));

    if (!CryptGetProvParam(provider, PP_VERSION, version_bytes, &size, 0))
    {
        cas::error::ThrowLast();
    }

    const auto major = (version >> 8) & 0xFF;
    const auto minor = version & 0xFF;

    handler(major, minor);
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

        cas::crypto::Provider provider(provider_name, provider_type);

        //
        // Now let's enumerate some parameters, for instance
        // version and all supported algorithms.
        //

        QueryVersion(provider, [](DWORD major, DWORD minor) {
            std::wcout << std::format(L"Provider's version: {}.{}\n", major, minor);
        });

        EnumerateAlgorithms(provider, [](const PROV_ENUMALGS_EX& alg) {
            std::cout << std::format(R"(Algorithm identifier: 0x{:08x}; key bits: {:4}; name: "{}" ({}))",
                             alg.aiAlgid, alg.dwDefaultLen, alg.szLongName, alg.szName)
                      << std::endl;
        });

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
