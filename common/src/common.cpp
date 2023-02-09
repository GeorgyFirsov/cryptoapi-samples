#include "common.hpp"


namespace cas {

std::wstring ErrorMessage(DWORD error_code) noexcept
{
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;

    LPWSTR buffer       = nullptr;
    const DWORD written = FormatMessage(flags, nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring result;

    if (written)
    {
        result.assign(buffer, written);
        LocalFree(buffer);
    }

    return result;
}

}  // namespace cas
