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
// Own headers
//

#include "common.hpp"


/**
 * @brief Subject name
 */
static constexpr auto kSubject = "Georgy V. Firsov";


int wmain()
{
    try
    {
        //
        // Set Windows-1251 codepage
        //

        USE_CODEPAGE(cas::utils::kWin1251);

        //
        // Encode subject name
        //

        CERT_RDN_ATTR name_attribute = {
            const_cast<LPSTR>("2.5.4.3"),
            CERT_RDN_PRINTABLE_STRING,
            strlen(kSubject),
            (BYTE*)kSubject
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

        //
        // Get subject's public key info
        //

        cas::crypto::Provider provider(PROV_RSA_FULL);
        cas::crypto::PublicKeyInfo public_key_info(provider, AT_SIGNATURE);

        //
        // Fill certificate request
        //

        CERT_REQUEST_INFO certificate_request {};
        certificate_request.dwVersion            = CERT_REQUEST_V1;
        certificate_request.cAttribute           = 0;
        certificate_request.rgAttribute          = nullptr;
        certificate_request.Subject.cbData       = encoded_name.size();
        certificate_request.Subject.pbData       = encoded_name.data();
        certificate_request.SubjectPublicKeyInfo = *public_key_info;

        //
        // Sign certificate request with exchange key
        //

        CRYPT_ALGORITHM_IDENTIFIER signature_algorithm {};
        signature_algorithm.pszObjId = const_cast<LPSTR>(szOID_OIWSEC_sha1RSASign);

        const auto signed_request = cas::crypto::SignAndEncodeCertificate(provider, AT_KEYEXCHANGE,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
            &certificate_request, &signature_algorithm);

        //
        // Just print encoded request
        //

        std::wcout << L"Certificate request in ASN.1 encoding:\n";
        cas::utils::DumpHex(signed_request, std::wcout);

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
