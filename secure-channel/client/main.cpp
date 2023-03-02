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
#include "utils.hpp"
#include "protocol.hpp"


/**
 * @brief Initiates a connection with a server using message queue.
 */
void InitiateConnection(sc::utils::FilePipe& pipe)
{
    //
    // Just send current process identifier to server.
    //

    sc::proto::sec_bytes pid_buffer(sizeof(DWORD), 0);
    *reinterpret_cast<DWORD*>(pid_buffer.data()) = GetCurrentProcessId();

    pipe.SendMessage<sc::proto::Payload>(pid_buffer);
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
        // Open server's message queue
        //

        sc::utils::FilePipe pipe(sc::proto::kQueueName, sc::proto::kServerMessageEvent,
            sc::proto::kClientMessageEvent);

        //
        // Initiate connection with server
        //

        InitiateConnection(pipe);

        std::wcout << L"Connection request sent\n";

        //
        // Generate exchange key pair
        //

        cas::crypto::Provider provider(PROV_RSA_AES);
        cas::crypto::Key exchange_key(provider, AT_KEYEXCHANGE);

        std::wcout << L"Exchange key generated successfully\n";

        //
        // Export exchange public key and sent to the server
        //

        const auto exchange_key_buffer = exchange_key.Export(PUBLICKEYBLOB);
        pipe.SendMessage<sc::proto::PublicKey>(exchange_key_buffer);

        std::wcout << L"Exchange public key sent successfully\n";

        //
        // Receive and import session key
        //

        const auto session_key_buffer = pipe.ReceiveMessage<sc::proto::SymmetricKey>();
        cas::crypto::Key session_key(provider, session_key_buffer, exchange_key);

        std::wcout << L"Session key received and imported successfully\n";

        //
        // Receive and import signature verification key
        //

        const auto signature_key_buffer = pipe.ReceiveMessage<sc::proto::PublicKey>();
        cas::crypto::Key signature_key(provider, signature_key_buffer);

        std::wcout << L"Signature verification key received and imported successfully\n";

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
