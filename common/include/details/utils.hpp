/**
 * @file utils.hpp
 * @brief Some helper stuff
 */

#pragma once

//
// Windows headers
//

#include "details/windows.hpp"
#include <atlsync.h>


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
 * @brief Class, that wraps console control handler and provides an
 *        event, that triggers when Ctrl+C or Ctrl+Break is hit or
 *        console is about to be closed.
 */
class StopHandler final
{
    StopHandler(const StopHandler&)            = delete;
    StopHandler& operator=(const StopHandler&) = delete;

    StopHandler(StopHandler&&)            = delete;
    StopHandler& operator=(StopHandler&&) = delete;

public:
    /**
     * @brief Constructor. Just calls SetConsoleCtrlHandler to set new
     *        console control handler.
     */
    StopHandler();

    /**
     * @brief Destructor. Calls SetConsoleCtrlHandler to remove intsalled
     *        in constructor control handler.
     */
    ~StopHandler();

    /**
     * @brief Get event, that becomes signaled when Ctrl+C or Ctrl+Break
     *        are hit or console is closed.
     */
    operator HANDLE() const noexcept { return event_; }

private:
    static BOOL WINAPI ControlHandler(DWORD control_type);

private:
    // Well, ControlHandler cannot accept user-defined parameters, so
    // this event will be static to make ControlHandler able to set it
    // to signaled state.
    static ATL::CEvent event_;
};

}  // namespace cas::utils
