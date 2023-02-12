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


/**
 * 
 */
class message_queue final
{
public:
    /**
     * 
     */
    using queue_t = ipc::message_queue;

    /**
     * 
     */
    using size_type = queue_t::size_type;

public:
    /**
     * 
     */
    explicit message_queue(const char* name, size_type max_number, size_type max_size)
        : queue_(ipc::create_only, name, max_number, max_size)
        , name_(name)
    { }

    /**
     * 
     */
    ~message_queue()
    {
        ipc::message_queue::remove(name_.c_str());
    }

    /**
     * 
     */
    queue_t* operator->() noexcept { return &queue_; }

private:
    // Queue itself
    queue_t queue_;

    // Queue name
    std::string name_;
};


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

        message_queue queue(sc::proto::kQueueName,
            sc::proto::kMaxMessageNumber, sc::proto::kMaxMessageSize);

        //
        // Create a signature key pair and symmetric session key
        //

        cas::crypto::Provider signature_provider(PROV_DSS);
        cas::crypto::Key signature_key(signature_provider, CALG_DSS_SIGN);

        cas::crypto::Provider symmetric_provider(PROV_RSA_AES);
        cas::crypto::Key session_key(symmetric_provider, CALG_AES_256);

        //
        // Receive and import exchange public key
        //

        unsigned int priority                  = 0;
        message_queue::size_type received_size = 0;
        cas::crypto::sec_vector<unsigned char> receive_buffer(sc::proto::kMaxMessageSize, 0);

        queue->receive(receive_buffer.data(), receive_buffer.size(), received_size, priority);
        const auto exchange_key_header = reinterpret_cast<sc::proto::PublicKeyHeaderMessage*>(
            receive_buffer.data());

        if (received_size != sizeof(sc::proto::PublicKeyHeaderMessage) ||
            exchange_key_header->header.signature != sc::proto::kPublicKeyHeaderSignature)
        {
            cas::error::Throw(ERROR_INVALID_DATA);
        }

        const auto keys_size = exchange_key_header->size;

        queue->receive(receive_buffer.data(), receive_buffer.size(), received_size, priority);
        if (received_size != keys_size)
        {
            cas::error::Throw(ERROR_INVALID_DATA);
        }

        cas::crypto::Provider exchange_provider(PROV_RSA_FULL);
        cas::crypto::Key exchange_key(exchange_provider, receive_buffer.data(), received_size);

        //
        // Export symmetric key using exchange key
        //

        DWORD buffer_size = 0;
        session_key.Export(exchange_key, PLAINTEXTKEYBLOB, nullptr, buffer_size);

        cas::crypto::sec_vector<unsigned char> session_key_buffer(buffer_size, 0);
        session_key.Export(exchange_key, PLAINTEXTKEYBLOB, session_key_buffer.data(), buffer_size);

        sc::proto::SymmetricKeyHeaderMessage session_key_header = {};
        session_key_header.header.signature                     = sc::proto::kSymmetricKeyHeaderSignature;
        session_key_header.size                                 = buffer_size;

        queue->send(&session_key_header, sizeof(session_key_header), sc::proto::kMessagePriority);
        queue->send(session_key_buffer.data(), session_key_buffer.size(), sc::proto::kMessagePriority);

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
