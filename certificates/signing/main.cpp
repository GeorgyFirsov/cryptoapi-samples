//
// Windows headers
//

#include "windows.hpp"
#include <wincrypt.h>


//
// STL headers
//

#include <iostream>
#include <stdexcept>


//
// Own headers
//

#include "common.hpp"


int wmain()
{
    try
    {
        //
        // TODO
        //

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;

        return -1;
    }
}
