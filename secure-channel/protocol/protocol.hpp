/**
 * @file protocol.hpp
 * @brief File with protocol description for client and server interaction
 */

#pragma once

namespace sc::proto {

/**
 * 
 */
inline constexpr auto kQueueName = "secure-channel-queue";


/**
 * 
 */
inline constexpr auto kMaxMessageNumber = 1024;


/**
 * 
 */
inline constexpr auto kMaxMessageSize = 4096;


/**
 * 
 */
inline constexpr auto kMessagePriority = 1;


/**
 *
 */
struct MessageHeader
{
    unsigned long signature; /**<  */
};


/**
 * 
 */
inline constexpr unsigned long kPublicKeyHeaderSignature = 0xCAFEBABE;

/**
 * 
 */
struct PublicKeyHeaderMessage
{
    MessageHeader header; /**<  */
    unsigned long size;   /**<  */
};


/**
 * 
 */
inline constexpr unsigned long kSymmetricKeyHeaderSignature = 0xDEADBEEF;

/**
 * 
 */
struct SymmetricKeyHeaderMessage
{
    MessageHeader header; /**<  */
    unsigned long size;   /**<  */
};

}  // namespace sc::proto
