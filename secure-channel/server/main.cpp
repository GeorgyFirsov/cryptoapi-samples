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
 * @brief Message queue wrapper for automatic destruction of 
 *        internal boost queue.
 */
class message_queue final
{
public:
    /**
     * @brief Internal queue type.
     */
    using queue_t = ipc::message_queue;

    /**
     * @brief Type, that represents size-related quantities.
     */
    using size_type = queue_t::size_type;

public:
    /**
     * @brief Constructor. Creates a named queue.
     */
    explicit message_queue(const char* name, size_type max_number, size_type max_size)
        : queue_(ipc::create_only, name, max_number, max_size)
        , name_(name)
    { }

    /**
     * @brief Destructor. Destroys the queue.
     */
    ~message_queue()
    {
        ipc::message_queue::remove(name_.c_str());
    }

    /**
     * @brief Operator for "transparent" queue interaction.
     */
    queue_t* operator->() noexcept { return &queue_; }

    /**
     * @brief Operator for implicit type casting.
     */
    operator queue_t&() noexcept { return queue_; }

private:
    queue_t queue_;    /**< Queue itself */
    std::string name_; /**< Queue name */
};


/**
 * @brief Receives a client's PID and returns it.
 */
DWORD GetClientPid(ipc::message_queue& queue)
{
    const auto raw_pid = sc::utils::ReceiveMessage<sc::proto::Payload>(queue);
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

        message_queue queue(sc::proto::kQueueName,
            sc::proto::kMaxMessageNumber, sc::proto::kMaxMessageSize);

        //
        // Wait for client connection and open its process handle
        //

        std::wcout << L"Waiting for connections...\n";

        cas::utils::Process client(GetClientPid(queue));

        std::wcout << L"New connection received\n";

        //
        // Create a signature key pair and symmetric session key
        //

        cas::crypto::Provider signature_provider(PROV_RSA_AES);
        cas::crypto::Key signature_key(signature_provider, CALG_RSA_SIGN);

        cas::crypto::Provider symmetric_provider(PROV_RSA_AES);
        cas::crypto::Key session_key(symmetric_provider, CALG_AES_256);

        std::wcout << L"Signature key pair and symmetric session keys created successfully\n";

        //
        // Receive and import exchange public key
        //

        const auto exchange_key_buffer = sc::utils::ReceiveMessage<sc::proto::PublicKey>(queue);

        cas::crypto::Provider exchange_provider(PROV_RSA_AES);
        cas::crypto::Key exchange_key(exchange_provider, exchange_key_buffer);

        std::wcout << L"Exchange key received and imported successfully\n";

        //
        // Export symmetric key using exchange key and send to client
        //

        const auto session_key_buffer = session_key.Export(exchange_key, PLAINTEXTKEYBLOB);
        sc::utils::SendMessage<sc::proto::SymmetricKey>(queue, session_key_buffer);

        std::wcout << L"Symmetric session key sent to client successfully\n";

        //
        // Export signature verification key and send to client too
        //

        const auto signature_key_buffer = signature_key.Export(PUBLICKEYBLOB);
        sc::utils::SendMessage<sc::proto::PublicKey>(queue, signature_key_buffer);

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
