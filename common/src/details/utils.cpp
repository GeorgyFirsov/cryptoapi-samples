/**
 * @file utils.hpp
 * @brief Some helper stuff implementation
 */


#include "details/utils.hpp"
#include "details/error.hpp"


namespace cas::utils {

ATL::CEvent StopHandler::event_(TRUE, FALSE);


StopHandler::StopHandler()
{
    if (!SetConsoleCtrlHandler(&StopHandler::ControlHandler, TRUE))
    {
        error::ThrowLast();
    }
}


StopHandler::~StopHandler()
{
    SetConsoleCtrlHandler(&StopHandler::ControlHandler, FALSE);
}


BOOL WINAPI StopHandler::ControlHandler(DWORD control_type)
{
    switch (control_type)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        return StopHandler::event_.Set();

    default:
        return FALSE;
    }
}

}  // namespace cas::utils
