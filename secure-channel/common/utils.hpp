/**
 * @file utils.hpp
 * @brief Helper functions.
 */

#pragma once

//
// Boost headers
//

#include <boost/interprocess/ipc/message_queue.hpp>


//
// Own headers
//

#include "protocol.hpp"


namespace sc::utils {

/**
 * @brief Receive a message from queue (synchronous operation).
 *        Message type is determined by traits.
 */
template<typename Traits>
sc::proto::sec_bytes ReceiveMessage(boost::interprocess::message_queue& queue)
{
    constexpr auto kSignature = Traits::kSignature;

    unsigned int priority                                       = 0;
    boost::interprocess::message_queue::size_type received_size = 0;
    sc::proto::sec_bytes buffer(sc::proto::kMaxMessageSize, 0);

    queue.receive(buffer.data(), buffer.size(), received_size, priority);
    const auto exchange_key_header = reinterpret_cast<sc::proto::MessageHeader*>(buffer.data());

    if (received_size != sizeof(sc::proto::MessageHeader) || exchange_key_header->signature != kSignature)
    {
        cas::error::Throw(ERROR_INVALID_DATA);
    }

    const auto data_size = received_size;

    queue.receive(buffer.data(), buffer.size(), received_size, priority);
    if (received_size != data_size)
    {
        cas::error::Throw(ERROR_INVALID_DATA);
    }

    buffer.resize(data_size);
    return buffer;
}


/**
 * @brief Send message into message queue. Message type is determined by traits.
 */
template<typename Traits>
void SendMessage(boost::interprocess::message_queue& queue, const sc::proto::sec_bytes& buffer)
{
    constexpr auto kSignature = Traits::kSignature;

    sc::proto::MessageHeader header = {};
    header.signature                = kSignature;
    header.size                     = buffer.size();

    queue.send(&header, sizeof(header), sc::proto::kMessagePriority);
    queue.send(buffer.data(), buffer.size(), sc::proto::kMessagePriority);
}

}  // namespace sc::utils
