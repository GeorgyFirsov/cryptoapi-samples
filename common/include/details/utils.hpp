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
 * 
 */
class Event final
{
public:
    /**
     * 
     */
    enum class Disposition {
        kCreate,
        kOpen
    };

public:
    /**
     * 
     */
    explicit Event(Disposition disposition, LPCWSTR name, BOOL manual_reset = TRUE, BOOL initially_set = FALSE)
        : h_(CreateOrOpenEvent(disposition, name, manual_reset, initially_set))
    { }

    /**
     * 
     */
    ~Event()
    {
        if (h_)
        {
            CloseHandle(h_);
        }
    }

    /**
     * 
     */
    void Set()
    {
        if (!SetEvent(h_))
        {
            error::ThrowLast();
        }
    }

    /**
     * 
     */
    void Reset()
    {
        if (!ResetEvent(h_))
        {
            error::ThrowLast();
        }
    }

    /**
     * 
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

}  // namespace cas::utils
