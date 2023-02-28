/**
 * @file protocol.hpp
 * @brief File with protocol description for client and server interaction
 */

#pragma once

#include "common.hpp"


namespace sc::proto {

/**
 * @brief Type of secure buffer with bytes.
 */
using sec_bytes = cas::crypto::sec_vector<unsigned char>;


/**
 * @brief Shared message queue name.
 */
inline constexpr auto kQueueName = "secure-channel-queue";


/**
 * @brief Maximum message queue size.
 */
inline constexpr auto kMaxMessageNumber = 1024;


/**
 * @brief Maximum message size.
 */
inline constexpr auto kMaxMessageSize = 4096;


/**
 * @brief Messages' priority.
 */
inline constexpr auto kMessagePriority = 1;


/**
 * @brief Header of each message.
 */
struct MessageHeader
{
    unsigned long signature; /**< Signature to verify integrity */
    unsigned long size;      /**< Size of payload followed in subsequent message */
};


/**
 * @brief Traits for public key message.
 */
struct PublicKey
{
    static constexpr unsigned long kSignature = 0xCAFEBABE;
};


/**
 * @brief Traits for symmetric key message.
 */
struct SymmetricKey
{
    static constexpr unsigned long kSignature = 0xDEADBEEF;
};


/**
 * @brief Traits for simple pyload.
 */
struct Payload
{
    static constexpr unsigned long kSignature = 0XBADF00D;
};

}  // namespace sc::proto
