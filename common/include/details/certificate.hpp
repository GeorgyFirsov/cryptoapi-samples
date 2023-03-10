/**
 * @file certificate.hpp
 * @brief Certificate-related functions and classes, that wrap 
 *        high-level CryptoAPI interface.
 */

#pragma once

//
// Windows headers
//

#include "windows.hpp"
#include <wincrypt.h>


//
// Library headers
//

#include "details/crypto.hpp"


namespace cas::crypto {

/**
 * @brief Wrapper over HCERTSTORE. Destroys handle at a scope exit.
 */
class CertStore final
{
public:
    /**
     * @brief Opens a certificate store by calling CertOpenStore.
     */
    explicit CertStore(LPCSTR store_provider, DWORD encoding_type, DWORD flags, const void* parameter);

    /**
     * @brief Destructor. Just calls cas::CertStore::Clear.
     */
    ~CertStore();

    /**
     * @brief Frees a wrapped store handle.
     */
    void Clear() noexcept;

    /**
     * @brief Get the internal store handle.
     */
    operator HCERTSTORE() const noexcept { return store_; }

private:
    HCERTSTORE store_; /**< Internal store handle */
};


/**
 * @brief Wrapper over PCCERT_CONTEXT. Destroys handle at a scope exit.
 */
class Certificate final
{
private:
    /**
     * @brief Private constructor. Checks if passed pointer is not null.
     *        If it is null, then throws an exception.
     */
    Certificate(PCCERT_CONTEXT cert) noexcept;

public:
    /**
     * @brief Creates a self signed certificate via CertCreateSelfSignCertificate.
     */
    static Certificate CreateSelfSigned(HCRYPTPROV provider, PCERT_NAME_BLOB issuer, DWORD flags = 0,
        PCRYPT_KEY_PROV_INFO key_provider_info = nullptr, PCRYPT_ALGORITHM_IDENTIFIER signature_algorithm = nullptr,
        PSYSTEMTIME start_time = nullptr, PSYSTEMTIME end_time = nullptr, PCERT_EXTENSIONS extensions = nullptr);

    /**
     * @brief Looks for certificate in store via CertFindCertificateInStore.
     */
    static Certificate FindInStore(HCERTSTORE store, DWORD encoding_type, DWORD flags, DWORD find_type,
        const void* find_parameter, PCCERT_CONTEXT previous = nullptr);

    /**
     * @brief Just calls cas::crypto::Certificate::Clear.
     */
    ~Certificate();

    /**
     * @brief Releases certificate's resources.
     */
    void Clear() noexcept;

    /**
     * @brief Implicit cast operator.
     */
    operator PCCERT_CONTEXT() const noexcept { return cert_; }

    /**
     * @brief Obtains properties of the certificate.
     */
    sec_vector<unsigned char> GetProperty(DWORD property) const;

private:
    PCCERT_CONTEXT cert_; /**< Internal certificate */
};


/**
 * @brief Wrapper over PCERT_PUBLIC_KEY_INFO.
 */
class PublicKeyInfo final
{
public:
    /**
     * @brief Obtains structure via CryptExportPublicKeyInfo.
     */
    explicit PublicKeyInfo(HCRYPTPROV provider, DWORD key_specification,
        DWORD encoding_type = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);

    /**
     * @brief Implicit cast operator.
     */
    operator PCERT_PUBLIC_KEY_INFO() noexcept { return reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(buffer_.data()); }

private:
    sec_vector<unsigned char> buffer_; /**< Buffer with public key information */
};


/**
 * @brief Signs a message using given public key certificate.
 * 
 * Exploits a high-level interface instead of low-level one, as in previous function.
 */
sec_vector<unsigned char> SignMessage(PCCERT_CONTEXT signing_certificate, const sec_vector<unsigned char>& message);


/**
 * @brief Verifies message signature.
 * 
 * Exploits a high-level interface instead of low-level one, as in previous function.
 */
void VerifySignature(const sec_vector<unsigned char>& signed_message, DWORD signature_index = 0);


/**
 * @brief Wrapper over CryptSignAndEncodeCertificate.
 */
sec_vector<unsigned char> SignAndEncodeCertificate(HCRYPTPROV provider, DWORD key_specification, DWORD encoding_type,
    LPCSTR struct_type, const void* struct_data, PCRYPT_ALGORITHM_IDENTIFIER signature_algorithm);


/**
 * @brief Wrapper over CryptEncodeObject.
 */
sec_vector<unsigned char> EncodeObject(DWORD encoding_type, LPCSTR struct_type, const void* struct_data);

}  // namespace cas::crypto
