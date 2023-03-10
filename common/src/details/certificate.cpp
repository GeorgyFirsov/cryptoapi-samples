/**
 * @file certificate.cpp
 * @brief Certificate-related functions and classes, that wrap 
 *        high-level CryptoAPI interface.
 */

//
// Library headers
//

#include "details/certificate.hpp"
#include "details/error.hpp"


namespace cas::crypto {

CertStore::CertStore(LPCSTR store_provider, DWORD encoding_type, DWORD flags, const void* parameter)
    : store_(CertOpenStore(store_provider, encoding_type, 0, flags, parameter))
{
    if (!store_ && CERT_STORE_DELETE_FLAG != (CERT_STORE_DELETE_FLAG & flags))
    {
        error::ThrowLast();
    }
}


CertStore::~CertStore()
{
    Clear();
}


void CertStore::Clear() noexcept
{
    if (store_)
    {
        CertCloseStore(std::exchange(store_, nullptr), 0);
    }
}


Certificate::Certificate(PCCERT_CONTEXT cert) noexcept
    : cert_(cert)
{
    if (!cert_)
    {
        error::ThrowLast();
    }
}


/* static */ Certificate Certificate::CreateSelfSigned(HCRYPTPROV provider, PCERT_NAME_BLOB issuer, DWORD flags /* = 0 */,
    PCRYPT_KEY_PROV_INFO key_provider_info /* = nullptr */, PCRYPT_ALGORITHM_IDENTIFIER signature_algorithm /* = nullptr */,
    PSYSTEMTIME start_time /* = nullptr */, PSYSTEMTIME end_time /* = nullptr */, PCERT_EXTENSIONS extensions /* = nullptr */)
{
    return CertCreateSelfSignCertificate(provider, issuer, flags, key_provider_info, signature_algorithm,
        start_time, end_time, extensions);
}


/* static */ Certificate Certificate::FindInStore(HCERTSTORE store, DWORD encoding_type, DWORD flags, DWORD find_type,
    const void* find_parameter, PCCERT_CONTEXT previous /* = nullptr */)
{
    return CertFindCertificateInStore(store, encoding_type, flags, find_type, find_parameter, previous);
}


Certificate::~Certificate()
{
    Clear();
}


void Certificate::Clear() noexcept
{
    if (cert_)
    {
        CertFreeCertificateContext(std::exchange(cert_, nullptr));
    }
}


sec_vector<unsigned char> Certificate::GetProperty(DWORD property) const
{
    DWORD buffer_size = 0;
    if (!CertGetCertificateContextProperty(cert_, property, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> result(buffer_size, 0);
    if (!CertGetCertificateContextProperty(cert_, property, result.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return result;
}


PublicKeyInfo::PublicKeyInfo(HCRYPTPROV provider, DWORD key_specification,
    DWORD encoding_type /* = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING */)
    : buffer_()
{
    DWORD buffer_size = 0;
    if (!CryptExportPublicKeyInfo(provider, key_specification, encoding_type, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    buffer_.resize(buffer_size);
    if (!CryptExportPublicKeyInfo(provider, key_specification, encoding_type,
            reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(buffer_.data()), &buffer_size))
    {
        error::ThrowLast();
    }
}


sec_vector<unsigned char> SignMessage(PCCERT_CONTEXT signing_certificate, const sec_vector<unsigned char>& message)
{
    CRYPT_SIGN_MESSAGE_PARA sign_patameters {};
    sign_patameters.cbSize                 = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    sign_patameters.dwMsgEncodingType      = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
    sign_patameters.pSigningCert           = signing_certificate;
    sign_patameters.HashAlgorithm.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
    sign_patameters.cMsgCert               = 1;
    sign_patameters.rgpMsgCert             = &signing_certificate;

    auto message_data = message.data();
    auto message_size = static_cast<DWORD>(message.size());

    DWORD buffer_size = 0;
    if (!CryptSignMessage(&sign_patameters, FALSE, 1, &message_data, &message_size, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> result(buffer_size, 0);
    if (!CryptSignMessage(&sign_patameters, FALSE, 1, &message_data, &message_size, result.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return result;
}


void VerifySignature(const sec_vector<unsigned char>& signed_message, DWORD signature_index /* = 0 */)
{
    CRYPT_VERIFY_MESSAGE_PARA verify_parameters {};
    verify_parameters.cbSize                   = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    verify_parameters.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    if (!CryptVerifyMessageSignature(&verify_parameters, signature_index, signed_message.data(),
            signed_message.size(), nullptr, nullptr, nullptr))
    {
        error::ThrowLast();
    }
}


sec_vector<unsigned char> SignAndEncodeCertificate(HCRYPTPROV provider, DWORD key_specification, DWORD encoding_type,
    LPCSTR struct_type, const void* struct_data, PCRYPT_ALGORITHM_IDENTIFIER signature_algorithm)
{
    DWORD buffer_size = 0;
    if (!CryptSignAndEncodeCertificate(provider, key_specification, encoding_type, struct_type,
            struct_data, signature_algorithm, nullptr, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> result(buffer_size, 0);
    if (!CryptSignAndEncodeCertificate(provider, key_specification, encoding_type, struct_type,
            struct_data, signature_algorithm, nullptr, result.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return result;
}


sec_vector<unsigned char> EncodeObject(DWORD encoding_type, LPCSTR struct_type, const void* struct_data)
{
    DWORD buffer_size = 0;
    if (!CryptEncodeObject(encoding_type, struct_type, struct_data, nullptr, &buffer_size))
    {
        error::ThrowLast();
    }

    sec_vector<unsigned char> result(buffer_size, 0);
    if (!CryptEncodeObject(encoding_type, struct_type, struct_data, result.data(), &buffer_size))
    {
        error::ThrowLast();
    }

    return result;
}

}  // namespace cas::crypto
