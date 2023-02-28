#
# client depends on Boost.Program_options
#
find_package(Boost REQUIRED)

#
# Directories
#
set(CAS_SC_CLIENT_ROOT			${CAS_SECURE_CHANNEL}/client)
set(CAS_SC_CLIENT_INCLUDE_DIRS	${Boost_INCLUDE_DIR}
								${CAS_SC_COMMON_INCLUDE})

#
# Sources and headers
#
set(CAS_SC_CLIENT_SOURCE_FILES	${CAS_SC_CLIENT_ROOT}/main.cpp)

set(CAS_SC_CLIENT_HEADER_FILES	)

set(CAS_SC_CLIENT_SOURCES		${CAS_SC_CLIENT_SOURCE_FILES}
								${CAS_SC_CLIENT_HEADER_FILES})

#
# App itself
#
add_executable(client			${CAS_SC_CLIENT_SOURCES})

#
# Additional include directories
#
target_include_directories(client PRIVATE ${CAS_SC_CLIENT_INCLUDE_DIRS})

#
# Link with common
#
target_link_libraries(client PRIVATE common)
target_link_libraries(client PRIVATE ${Boost_LIBRARIES})
