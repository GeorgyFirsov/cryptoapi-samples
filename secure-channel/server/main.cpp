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
#include <vector>


//
// Own headers
//

#include "common.hpp"
#include "pipe.hpp"
#include "protocol.hpp"


/**
 * @brief Receives a client's PID and returns it.
 */
DWORD GetClientPid(sc::ipc::FilePipe& pipe)
{
    const auto raw_pid = pipe.ReceiveMessage<sc::proto::Payload>();
    return *reinterpret_cast<const DWORD*>(raw_pid.data());
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
        // Create message queue to interact with a client
        //

        sc::ipc::FilePipe pipe(sc::proto::kQueueName, sc::proto::kServerMessageEvent,
            sc::proto::kClientMessageEvent, sc::proto::kMaxMessageNumber, sc::proto::kMaxMessageSize);

        //
        // Wait for client connection and open its process handle
        //

        std::wcout << L"Waiting for connections...\n";

        cas::utils::Process client(GetClientPid(pipe));

        std::wcout << L"New connection received\n";

        //
        // Create a signature key pair and symmetric session key
        //

        cas::crypto::Provider provider(PROV_RSA_AES);
        cas::crypto::Key signature_key(provider, AT_SIGNATURE);
        cas::crypto::Key session_key(provider, CALG_AES_256, CRYPT_EXPORTABLE);

        std::wcout << L"Signature key pair and symmetric session keys created successfully\n";

        //
        // Receive and import exchange public key
        //

        const auto exchange_key_buffer = pipe.ReceiveMessage<sc::proto::PublicKey>();
        cas::crypto::Key exchange_key(provider, exchange_key_buffer);

        std::wcout << L"Exchange key received and imported successfully\n";

        //
        // Export symmetric key using exchange key and send to client
        //

        const auto session_key_buffer = session_key.Export(exchange_key, SIMPLEBLOB);
        pipe.SendMessage<sc::proto::SymmetricKey>(session_key_buffer);

        std::wcout << L"Symmetric session key sent to client successfully\n";

        //
        // Export signature verification key and send to client too
        //

        const auto signature_key_buffer = signature_key.Export(PUBLICKEYBLOB);
        pipe.SendMessage<sc::proto::PublicKey>(signature_key_buffer);

        std::wcout << L"Signature key sent to client successfully\n";

        //
        // Wait until client process ends to close message queue safe.
        //

        std::wcout << L"Waiting for client process to end...\n";

        client.Wait();

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
