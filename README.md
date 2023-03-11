> **Warning**
> This repository is a public archive for successors

# cryptoapi-samples

Labs for development and exploitation of cryptographic infrastructure course. National Research Nuclear University MEPhI, Spring 2023.

## List of implemented tasks

- [Enumerating supported cryptoprovider types][1]
- [Enumerating installed cryptoproviders of a given type][2]
- [Enumerating of cryptographic algorithms supported by a given provider][3]
- [Creating and removing a named key container for a given provider][4]
- [Symmetric key exchange between two processes using exchange key pair][5]
- [Sharing a verification key between two processes][5]
- [Encrypting and signing a message using][5] ["Base Cryptography Functions"][ext-1]
- [Decrypting and verifying message's signature using "Base Cryptography Functions"][5]
- [Creating a certificate request][6]
- [Creating (removing) certificate storage, importing (removing) certificate into (from) storage][7]
- [Signing a message and verifying message's signature using][8] ["Simplified Message Functions"][ext-2]

[1]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/cryptoproviders/enum-provider-types
[2]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/cryptoproviders/enum-providers
[3]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/cryptoproviders/provider-params
[4]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/cryptoproviders/container
[5]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/secure-channel
[6]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/certificates/request
[7]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/certificates/store
[8]: https://github.com/GeorgyFirsov/cryptoapi-samples/tree/main/certificates/signing

[ext-1]: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions#base-cryptography-functions
[ext-2]: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions#simplified-message-functions
