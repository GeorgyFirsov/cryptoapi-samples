#
# Directories
#
set(CAS_COMMON_INCLUDE_ROOT	${CAS_COMMON}/include)
set(CAS_COMMON_DETAILS_INC	${CAS_COMMON_INCLUDE_ROOT}/details)
set(CAS_COMMON_SOURCE_ROOT	${CAS_COMMON}/src)
set(CAS_COMMON_DETAILS_SRC	${CAS_COMMON_SOURCE_ROOT}/details)

#
# Sources and headers
#
set(CAS_COMMON_SOURCE_FILES	${CAS_COMMON_DETAILS_SRC}/crypto.cpp
							${CAS_COMMON_DETAILS_SRC}/network.cpp
							${CAS_COMMON_DETAILS_SRC}/utils.cpp)

set(CAS_COMMON_HEADER_FILES	${CAS_COMMON_INCLUDE_ROOT}/common.hpp
							${CAS_COMMON_DETAILS_INC}/crypto.hpp
							${CAS_COMMON_DETAILS_INC}/error.hpp
							${CAS_COMMON_DETAILS_INC}/network.hpp
							${CAS_COMMON_DETAILS_INC}/utils.hpp)

set(CAS_COMMON_SOURCES		${CAS_COMMON_SOURCE_FILES}
							${CAS_COMMON_HEADER_FILES})

#
# Library itself
#
add_library(common			${CAS_COMMON_SOURCES})

#
# Link with WinSock2
#
target_link_libraries(common PRIVATE Ws2_32)

#
# Includes
#
target_include_directories(common PRIVATE ${CAS_COMMON_INCLUDE_ROOT})