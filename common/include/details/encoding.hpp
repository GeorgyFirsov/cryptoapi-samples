/**
 * @file encoding.hpp
 * @brief Encoding functions.
 */

//
// Windows headers
//

#include "windows.hpp"
#include <atlenc.h>


//
// STL headers
//

#include <vector>
#include <string>


//
// Library headers
//

#include "details/error.hpp"
#include "details/crypto.hpp"


namespace cas::enc {

/**
 * @brief Encodes binary data into Base64 string.
 */
template<typename Alloc>
std::string Base64Encode(const std::vector<unsigned char, Alloc>& data)
{
    const auto data_size = static_cast<int>(data.size());
    auto buffer_size     = ATL::Base64EncodeGetRequiredLength(data_size, ATL_BASE64_FLAG_NOCRLF);

    std::string result(buffer_size, 0);
    if (!ATL::Base64Encode(data.data(), data_size, result.data(), &buffer_size, ATL_BASE64_FLAG_NOCRLF))
    {
        error::Throw(ERROR_UNIDENTIFIED_ERROR);
    }

    result.resize(buffer_size);
    return result;
}


/**
 * @brief Decodes Base64 string into binary data.
 */
template<typename Alloc = crypto::erasing_adaptor<std::allocator<unsigned char>>>
std::vector<unsigned char, Alloc> Base64Decode(const std::string& encoded)
{
    const auto encoded_size = static_cast<int>(encoded.length());
    auto buffer_size        = ATL::Base64DecodeGetRequiredLength(encoded_size);

    std::vector<unsigned char, Alloc> result(buffer_size, 0);
    if (!ATL::Base64Decode(encoded.c_str(), encoded_size, result.data(), &buffer_size))
    {
        error::Throw(ERROR_UNIDENTIFIED_ERROR);
    }

    result.resize(buffer_size);
    return result;
}

}  // namespace cas::enc
