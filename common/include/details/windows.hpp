/**
 * @file windows.hpp
 * @brief Proper Windows headers include
 */

#pragma once

//
// Configure Windows.h header
//

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX


//
// Minimum supported Windows version
//

#ifndef WINVER
#   define WINVER 0x0601  // Windows 7
#endif

#ifndef _WIN32_WINNT
#   define _WIN32_WINNT 0x0601  // Windows 7
#endif


//
// Windows headers themselves
//

#include <Windows.h>
#include <wincrypt.h>
