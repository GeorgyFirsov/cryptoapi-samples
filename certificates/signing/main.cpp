//
// Windows headers
//

#include "windows.hpp"
#include <wincrypt.h>


//
// STL headers
//

#include <algorithm>
#include <ranges>
#include <iostream>
#include <stdexcept>


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
#include "store.hpp"


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
static constexpr auto kCert            = "cert";
static constexpr auto kCertDefinition  = "cert,c";
static constexpr auto kCertDescription = "use specified certificate for signing";


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
            (kCertDefinition, po::value<std::string>()->required(), kCertDescription)
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
        // Get key SHA1 hash
        //

        const auto encoded_hash = variables[kCert].as<std::string>();
        auto hash               = cas::enc::Base64Decode(encoded_hash);
        CRYPT_HASH_BLOB hash_blob { hash.size(), hash.data() };

        //
        // Open store and look for certificate
        //

        cas::crypto::CertStore store(CERT_STORE_PROV_SYSTEM, 0, CERT_SYSTEM_STORE_CURRENT_USER, cert::kStoreName);
        const auto cert = cas::crypto::Certificate::FindInStore(store, 0, 0, CERT_FIND_SHA1_HASH, &hash_blob);

        //
        // Sign message
        //

        cas::crypto::sec_vector<unsigned char> message;
        std::ranges::copy(std::views::iota(1, 51), std::back_inserter(message));

        std::wcout << L"Message:\n";
        cas::utils::DumpHex(message, std::wcout);

        const auto signed_message = cas::crypto::SignMessage(cert, message);

        std::wcout << L"\nSigned message:\n";
        cas::utils::DumpHex(signed_message, std::wcout);

        cas::crypto::VerifySignature(signed_message);

        std::wcout << L"\nMessage signature successfully verified\n";

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
