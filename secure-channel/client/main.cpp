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
#include "protocol.hpp"


//
// Just for simplicity
//

namespace ipc = boost::interprocess;


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
        // Generate exchange key pair
        //

        cas::crypto::Provider exchange_provider(PROV_RSA_FULL);
        cas::crypto::Key exchange_key(exchange_provider, CALG_RSA_KEYX);

        //
        // Export exchange public key and sent to the server
        //

        DWORD buffer_size = 0;
        exchange_key.Export(PUBLICKEYBLOB, nullptr, buffer_size);

        cas::crypto::sec_vector<unsigned char> exchange_key_buffer(buffer_size, 0);
        exchange_key.Export(PUBLICKEYBLOB, exchange_key_buffer.data(), buffer_size);

        sc::proto::PublicKeyHeaderMessage exchange_key_header = {};
        exchange_key_header.header.signature                  = sc::proto::kPublicKeyHeaderSignature;
        exchange_key_header.size                              = buffer_size;

        queue.send(&exchange_key_header, sizeof(exchange_key_header), sc::proto::kMessagePriority);
        queue.send(exchange_key_buffer.data(), exchange_key_buffer.size(), sc::proto::kMessagePriority);

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
