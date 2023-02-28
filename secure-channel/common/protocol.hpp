/**
 * @file protocol.hpp
 * @brief File with protocol description for client and server interaction
 */

#pragma once

#include "common.hpp"


namespace sc::proto {

/**
 * 
 */
using sec_bytes = cas::crypto::sec_vector<unsigned char>;


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
    unsigned long size;      /**< */
};


/**
 * 
 */
inline constexpr unsigned long kPublicKeyHeaderSignature = 0xCAFEBABE;


/**
 * 
 */
struct PublicKey
{
    static constexpr unsigned long kSignature = kPublicKeyHeaderSignature;
};


/**
 * 
 */
inline constexpr unsigned long kSymmetricKeyHeaderSignature = 0xDEADBEEF;

/**
 * 
 */
struct SymmetricKey
{
    static constexpr unsigned long kSignature = kSymmetricKeyHeaderSignature;
};

}  // namespace sc::proto
