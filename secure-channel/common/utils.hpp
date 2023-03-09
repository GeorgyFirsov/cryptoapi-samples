/**
 * @file utils.hpp
 * @brief Helper functions.
 */

//
// STL headers
//

#include <ostream>
#include <format>
#include <vector>


namespace sc::utils {

/**
 * @brief Prints data in hex.
 */
template<typename Alloc>
void DumpHex(const std::vector<unsigned char, Alloc>& data, std::wostream& out)
{
    static constexpr auto kColumns = 16;

    for (size_t idx = 0; idx < data.size(); ++idx)
    {
        if (idx % kColumns == 0 && idx)
        {
            out << L'\n';
        }

        out << std::format(L"{:02X} ", data[idx]);
    }
}

}  // namespace sc::utils
