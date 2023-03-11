//
// Windows headers
//

#include "windows.hpp"
#include <wincrypt.h>


//
// STL headers
//

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

static constexpr auto kOptionsHeader     = "Allowed options";
static constexpr auto kHelp              = "help";
static constexpr auto kHelpDefinition    = "help,h";
static constexpr auto kHelpDescription   = "display help message";
static constexpr auto kNew               = "new";
static constexpr auto kNewDefinition     = "new,n";
static constexpr auto kNewDescription    = "create new key container";
static constexpr auto kCreate            = "create";
static constexpr auto kCreateDefinition  = "create,c";
static constexpr auto kCreateDescription = "create new certificate";
static constexpr auto kDelete            = "delete";
static constexpr auto kDeleteDefinition  = "delete,d";
static constexpr auto kDeleteDescription = "delete certificate with given SHA1 hash";
static constexpr auto kPurge             = "purge";
static constexpr auto kPurgeDefinition   = "purge,p";
static constexpr auto kPurgeDescription  = "removes everything (stores, certs, ...) created by the app";


/**
 * @brief Creates a self signed certificate and adds it into a store
 */
cas::crypto::Certificate CreateSelfSignedCertificate(HCRYPTPROV provider)
{
    //
    // Encode issuer name
    //

    CERT_RDN_ATTR name_attribute = {
        const_cast<LPSTR>("2.5.4.3"),
        CERT_RDN_PRINTABLE_STRING,
        strlen(cert::kCertIssuer),
        (BYTE*)cert::kCertIssuer
    };

    CERT_RDN rdn = {
        1,
        &name_attribute
    };

    CERT_NAME_INFO name = {
        1,
        &rdn
    };

    auto encoded_name = cas::crypto::EncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, X509_NAME, &name);
    CERT_NAME_BLOB issuer { encoded_name.size(), encoded_name.data() };

    //
    // Now let's create certificate itself. It will be valid from the current
    // moment of time for one year.
    // SHA256RSA will be used as signature algorithm.
    // Certificate will not contain any extensions.
    //

    CRYPT_ALGORITHM_IDENTIFIER signature_algorithm {};
    signature_algorithm.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);

    return cas::crypto::Certificate::CreateSelfSigned(provider, &issuer, 0, nullptr, &signature_algorithm);
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
            (kCreateDefinition, kCreateDescription)
            (kNewDefinition, kNewDescription)
            (kDeleteDefinition, po::value<std::string>(), kDeleteDescription)
            (kPurgeDefinition, kPurgeDescription)
            ;
        // clang-format on

        po::variables_map variables;
        po::store(po::parse_command_line(argc, argv, options), variables);

        if (!variables[kHelp].empty())
        {
            std::cout << options << std::endl;
            return -1;
        }
        
        //
        // Well.. Actually it will be much better to check if passed command line 
        // parameters are valid (some of them are mutually exclusive), but it is not 
        // a purpose of the task, so I omit these checks here
        //

        po::notify(variables);

        //
        // Open certificate store
        //

        cas::crypto::CertStore store(CERT_STORE_PROV_SYSTEM, 0, CERT_SYSTEM_STORE_CURRENT_USER, cert::kStoreName);

        //
        // Check if one requests to delete certificate
        //

        if (!variables[kCreate].empty())
        {
            //
            // Generate CA key pair
            // Key container will be created if requested
            //

            const auto flags = variables[kNew].empty()
                                 ? 0
                                 : CRYPT_NEWKEYSET;

            cas::crypto::Provider provider(cert::kKeyContainer, nullptr, PROV_RSA_FULL, flags);
            cas::crypto::Key key(provider, AT_SIGNATURE);

            //
            // Create self signed certificate and import to store
            //

            const auto cert = CreateSelfSignedCertificate(provider);
            if (!CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_NEW, nullptr))
            {
                cas::error::ThrowLast();
            }

            //
            // Print hash
            //

            const auto certificate_hash = cert.GetProperty(CERT_SHA1_HASH_PROP_ID);

            std::wcout << L"Created certificate SHA1 hash:\n";
            cas::utils::DumpHex(certificate_hash, std::wcout);

            std::wcout << L"\nCreated certificate SHA1 hash in Base64:\n";
            std::cout << cas::enc::Base64Encode(certificate_hash);
        }
        else if (!variables[kDelete].empty())
        {
            //
            // Parse Base64 SHA1 hash of certificate
            //

            const auto encoded_hash = variables[kDelete].as<std::string>();
            auto hash               = cas::enc::Base64Decode(encoded_hash);
            CRYPT_HASH_BLOB hash_blob { hash.size(), hash.data() };

            //
            // Lookup certificate in store and delete it
            //

            const auto cert = cas::crypto::Certificate::FindInStore(store, 0, 0, CERT_FIND_SHA1_HASH, &hash_blob);
            if (!CertDeleteCertificateFromStore(cert))
            {
                cas::error::ThrowLast();
            }

            std::wcout << L"Certificate was removed successfully\n";
        }
        else if (!variables[kPurge].empty())
        {
            //
            // Delete key container
            //

#pragma warning(suppress : 26444)  // Unnamed local variable
            cas::crypto::Provider(cert::kKeyContainer, nullptr, PROV_RSA_FULL, CRYPT_DELETE_KEYSET);

            //
            // Delete cert store
            //

#pragma warning(suppress : 26444)  // Unnamed local variable
            cas::crypto::CertStore(CERT_STORE_PROV_SYSTEM, 0,
                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_DELETE_FLAG, cert::kStoreName);

            std::wcout << L"Application's data purged successfully\n";
        }

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
