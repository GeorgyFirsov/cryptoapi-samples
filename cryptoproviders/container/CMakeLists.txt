#
# container depends on Boost.Program_options
#
find_package(Boost COMPONENTS program_options REQUIRED)

#
# Directories
#
set(CAS_CONTAINER_ROOT			${CAS_CRYPTOPROVIDERS}/container)
set(CAS_CONTAINER_INCLUDE_DIRS	${Boost_INCLUDE_DIR})

#
# Sources and headers
#
set(CAS_CONTAINER_SOURCE_FILES	${CAS_CONTAINER_ROOT}/main.cpp)

set(CAS_CONTAINER_HEADER_FILES	)

set(CAS_CONTAINER_SOURCES		${CAS_CONTAINER_SOURCE_FILES}
								${CAS_CONTAINER_HEADER_FILES})

#
# App itself
#
add_executable(container		${CAS_CONTAINER_SOURCES})

#
# Additional include directories
#
target_include_directories(container PRIVATE ${CAS_CONTAINER_INCLUDE_DIRS})

#
# Link with common
#
target_link_libraries(container PRIVATE common)
target_link_libraries(container PRIVATE ${Boost_LIBRARIES})
