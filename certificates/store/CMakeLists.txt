#
# container depends on Boost.Program_options
#
find_package(Boost COMPONENTS program_options REQUIRED)

#
# Directories
#
set(CAS_CERT_STORE_ROOT			${CAS_CERTIFICATES}/store)
set(CAS_CERT_STORE_INCLUDE_DIRS	${Boost_INCLUDE_DIR})

#
# Sources and headers
#
set(CAS_CERT_STORE_SOURCE_FILES	${CAS_CERT_STORE_ROOT}/main.cpp)

set(CAS_CERT_STORE_HEADER_FILES	)

set(CAS_CERT_STORE_SOURCES		${CAS_CERT_STORE_SOURCE_FILES}
								${CAS_CERT_STORE_HEADER_FILES})

#
# App itself
#
add_executable(store			${CAS_CERT_STORE_SOURCES})

#
# Additional include directories
#
target_include_directories(store PRIVATE ${CAS_CERT_STORE_INCLUDE_DIRS})

#
# Link with common and Boost
#
target_link_libraries(store PRIVATE common)
target_link_libraries(store PRIVATE ${Boost_LIBRARIES})
