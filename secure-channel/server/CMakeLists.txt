#
# server depends on Boost.Program_options
#
find_package(Boost REQUIRED)

#
# Directories
#
set(CAS_SC_SERVER_ROOT			${CAS_SECURE_CHANNEL}/server)
set(CAS_SC_SERVER_INCLUDE_DIRS	${Boost_INCLUDE_DIR}
								${CAS_SC_PROTOCOL_INCLUDE})

#
# Sources and headers
#
set(CAS_SC_SERVER_SOURCE_FILES	${CAS_SC_SERVER_ROOT}/main.cpp)

set(CAS_SC_SERVER_HEADER_FILES	)

set(CAS_SC_SERVER_SOURCES		${CAS_SC_SERVER_SOURCE_FILES}
								${CAS_SC_SERVER_HEADER_FILES})

#
# App itself
#
add_executable(server			${CAS_SC_SERVER_SOURCES})

#
# Additional include directories
#
target_include_directories(server PRIVATE ${CAS_SC_SERVER_INCLUDE_DIRS})

#
# Link with common
#
target_link_libraries(server PRIVATE common)
target_link_libraries(server PRIVATE ${Boost_LIBRARIES})
