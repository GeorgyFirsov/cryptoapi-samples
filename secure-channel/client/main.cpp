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
#include <vector>


//
// Boost headers
//

#include <boost/interprocess/ipc/message_queue.hpp>


//
// Own headers
//

#include "common.hpp"
#include "utils.hpp"
#include "protocol.hpp"


//
// Just for simplicity
//

namespace ipc = boost::interprocess;


/**
 * @brief Initiates a connection with a server using message queue.
 */
void InitiateConnection(ipc::message_queue& queue)
{
    //
    // Just send current process identifier to server.
    //

    sc::proto::sec_bytes pid_buffer(sizeof(DWORD), 0);
    *reinterpret_cast<DWORD*>(pid_buffer.data()) = GetCurrentProcessId();

    sc::utils::SendMessage<sc::proto::Payload>(queue, pid_buffer);
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

        ipc::message_queue queue(ipc::open_only, sc::proto::kQueueName);

        //
        // Initiate connection with server
        //

        InitiateConnection(queue);

        //
        // Generate exchange key pair
        //

        cas::crypto::Provider exchange_provider(PROV_RSA_AES);
        cas::crypto::Key exchange_key(exchange_provider, CALG_RSA_KEYX);

        //
        // Export exchange public key and sent to the server
        //

        const auto exchange_key_buffer = exchange_key.Export(PUBLICKEYBLOB);
        sc::utils::SendMessage<sc::proto::PublicKey>(queue, exchange_key_buffer);

        //
        // Receive and import session key
        //

        const auto session_key_buffer = sc::utils::ReceiveMessage<sc::proto::SymmetricKey>(queue);

        cas::crypto::Provider symmetric_provider(PROV_RSA_AES);
        cas::crypto::Key session_key(symmetric_provider, session_key_buffer, exchange_key);

        //
        // Receive and import signature verification key
        //

        const auto signature_key_buffer = sc::utils::ReceiveMessage<sc::proto::PublicKey>(queue);

        cas::crypto::Provider signature_provider(PROV_RSA_AES);
        cas::crypto::Key signature_key(signature_provider, signature_key_buffer);

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
