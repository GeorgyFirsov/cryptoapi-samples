/**
 * @file utils.hpp
 * @brief Some helper stuff
 */

#pragma once

//
// Windows headers
//

#include "windows.hpp"
#include "details/error.hpp"


//
// STL headers
//

#include <format>
#include <vector>
#include <ostream>


namespace cas::utils {

/**
 * @brief Checks if specific flag is set in the bit mask.
 */
#define FLAG_ON(flag, flags) (!!((flags) & (flag)))


/**
 * @brief Sets a codepage for current application's console.
 */
#define USE_CODEPAGE(cp) static auto cp_init_ =        \
                             []() {                    \
                               SetConsoleCP(cp);       \
                               SetConsoleOutputCP(cp); \
                               return 0;               \
                             }()


/**
 * @brief Codepage identifier for Windows-1251.
 */
inline constexpr UINT kWin1251 = 1251;


/**
 * @brief Process handle wrapper.
 */
class Process final
{
    Process(const Process&)            = delete;
    Process& operator=(const Process&) = delete;

    Process(Process&&)            = delete;
    Process& operator=(Process&&) = delete;

public:
    /**
     * @brief Opens a process by its identifier.
     */
    explicit Process(DWORD pid)
        : h_(OpenProcess(SYNCHRONIZE, FALSE, pid))
    {
        if (!h_)
        {
            error::ThrowLast();
        }
    }

    /**
     * @brief Closes internal handle.
     */
    ~Process()
    {
        if (h_)
        {
            CloseHandle(h_);
        }
    }

    /**
     * @brief Waits until a wrapped process ends.
     */
    void Wait()
    {
        if (WAIT_FAILED == WaitForSingleObject(h_, INFINITE))
        {
            error::ThrowLast();
        }
    }

private:
    HANDLE h_; /**< Internal handle */
};


/**
 * @brief Event handle wrapper.
 */
class Event final
{
    Event(const Event&)            = delete;
    Event& operator=(const Event&) = delete;

    Event(Event&&)            = delete;
    Event& operator=(Event&&) = delete;

public:
    /**
     * @brief Event creation disposition
     */
    enum class Disposition
    {
        kCreate, /**< Create new event */
        kOpen    /**< Open existing named event */
    };

public:
    /**
     * @brief Opens named or creates any (named or unnamed) event.
     */
    explicit Event(Disposition disposition, LPCWSTR name, BOOL manual_reset = TRUE, BOOL initially_set = FALSE)
        : h_(CreateOrOpenEvent(disposition, name, manual_reset, initially_set))
    { }

    /**
     * @brief Closes internal handle.
     */
    ~Event()
    {
        if (h_)
        {
            CloseHandle(h_);
        }
    }

    /**
     * @brief Sets the event.
     */
    void Set()
    {
        if (!SetEvent(h_))
        {
            error::ThrowLast();
        }
    }

    /**
     * @brief Resets the event.
     */
    void Reset()
    {
        if (!ResetEvent(h_))
        {
            error::ThrowLast();
        }
    }

    /**
     * @brief Waits until the wrapped event will become signaled.
     */
    void Wait()
    {
        if (WAIT_FAILED == WaitForSingleObject(h_, INFINITE))
        {
            error::ThrowLast();
        }
    }

private:
    HANDLE CreateOrOpenEvent(Disposition disposition, LPCWSTR name, BOOL manual_reset, BOOL initially_set)
    {
        switch (disposition)
        {
        case Disposition::kCreate:
            return CreateEvent(nullptr, manual_reset, initially_set, name);
        case Disposition::kOpen:
            return OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, name);
        }

        error::Throw(ERROR_INVALID_PARAMETER);
    }

private:
    HANDLE h_; /**< Internal handle */
};


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

}  // namespace cas::utils
