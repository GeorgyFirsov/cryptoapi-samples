/**
 * @file utils.hpp
 * @brief Helper functions.
 */

#pragma once

//
// Windows headers
//

#include <windows.hpp>


//
// STL headers
// 

#include <string>


//
// Boost headers
//

#include <boost/interprocess/ipc/message_queue.hpp>


//
// Own headers
//

#include "protocol.hpp"
#include "common.hpp"


namespace sc::utils {

/**
 * @brief File-based interprocess communication pipe
 */
class FilePipe final
{
    using queue_t   = boost::interprocess::message_queue;
    using size_type = queue_t::size_type;
    using event_t   = cas::utils::Event;

private:
    static constexpr auto kDefaultQueue = "default-queue-name";

public:
    /**
     * @brief Constructs a pipe by creating new named queue and events.
     */
    explicit FilePipe(const char* queue_name, const wchar_t* server_event, const wchar_t* client_event,
        size_type max_number, size_type max_size)
        : queue_(boost::interprocess::create_only, queue_name ? queue_name : kDefaultQueue, max_number, max_size)
        , server_event_(event_t::Disposition::kCreate, server_event, FALSE, FALSE)
        , client_event_(event_t::Disposition::kCreate, client_event, FALSE, FALSE)
        , queue_name_(queue_name ? queue_name : kDefaultQueue)
        , is_server_(true)
    { }

    /**
     * @brief Constructs a pipe by opening existing queue and events.
     */
    explicit FilePipe(const char* queue_name, const wchar_t* server_event, const wchar_t* client_event)
        : queue_(boost::interprocess::open_only, queue_name ? queue_name : kDefaultQueue)
        , server_event_(event_t::Disposition::kOpen, server_event)
        , client_event_(event_t::Disposition::kOpen, client_event)
        , queue_name_(queue_name ? queue_name : kDefaultQueue)
        , is_server_(false)
    { }

    /**
     * @brief Destroys a pipe on server side.
     */
    ~FilePipe()
    {
        if (is_server_)
        {
            queue_t::remove(queue_name_.c_str());
        }
    }

    /**
     * @brief Send message into message queue. Message type is determined by traits.
     */
    template<typename Traits>
    void SendMessage(const sc::proto::sec_bytes& buffer)
    {
        constexpr auto kSignature = Traits::kSignature;

        sc::proto::MessageHeader header = {};
        header.signature                = kSignature;
        header.size                     = buffer.size();

        queue_.send(&header, sizeof(header), sc::proto::kMessagePriority);
        queue_.send(buffer.data(), buffer.size(), sc::proto::kMessagePriority);

        SendingEvent().Set();
    }

    /**
     * @brief Receive a message from queue (synchronous operation).
     *        Message type is determined by traits.
     */
    template<typename Traits>
    sc::proto::sec_bytes ReceiveMessage()
    {
        constexpr auto kSignature = Traits::kSignature;

        ReceivingEvent().Wait();

        unsigned int priority                                       = 0;
        boost::interprocess::message_queue::size_type received_size = 0;
        sc::proto::sec_bytes buffer(sc::proto::kMaxMessageSize, 0);

        queue_.receive(buffer.data(), buffer.size(), received_size, priority);
        const auto exchange_key_header = reinterpret_cast<sc::proto::MessageHeader*>(buffer.data());

        if (received_size != sizeof(sc::proto::MessageHeader) || exchange_key_header->signature != kSignature)
        {
            cas::error::Throw(ERROR_INVALID_DATA);
        }

        const auto data_size = exchange_key_header->size;

        queue_.receive(buffer.data(), buffer.size(), received_size, priority);
        if (received_size != data_size)
        {
            cas::error::Throw(ERROR_INVALID_DATA);
        }

        buffer.resize(data_size);
        return buffer;
    }

private:
    event_t& ReceivingEvent() noexcept
    {
        return is_server_ ? client_event_ : server_event_;
    }

    event_t& SendingEvent() noexcept
    {
        return is_server_ ? server_event_ : client_event_;
    }

private:
    queue_t queue_;          /**< File-based message queue */
    event_t server_event_;   /**< Event, that is set, when server sent a message */
    event_t client_event_;   /**< Event, that is set, when client sent a message */
    std::string queue_name_; /**< Name of queue */
    bool is_server_;         /**< Flags, that is true on server side only */
};

}  // namespace sc::utils
