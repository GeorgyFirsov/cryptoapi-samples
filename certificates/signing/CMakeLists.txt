#
# container depends on Boost.Program_options
#
find_package(Boost COMPONENTS program_options REQUIRED)

#
# Directories
#
set(CAS_CERT_SIGNING_ROOT			${CAS_CERTIFICATES}/signing)
set(CAS_CERT_SIGNING_INCLUDE_DIRS	${Boost_INCLUDE_DIR}
									${CAS_CERTIFICATES_COMMON_INCLUDE})

#
# Sources and headers
#
set(CAS_CERT_SIGNING_SOURCE_FILES	${CAS_CERT_SIGNING_ROOT}/main.cpp)

set(CAS_CERT_SIGNING_HEADER_FILES	)

set(CAS_CERT_SIGNING_SOURCES		${CAS_CERT_SIGNING_SOURCE_FILES}
									${CAS_CERT_SIGNING_HEADER_FILES})

#
# App itself
#
add_executable(signing				${CAS_CERT_SIGNING_SOURCES})

#
# Additional include directories
#
target_include_directories(signing PRIVATE ${CAS_CERT_SIGNING_INCLUDE_DIRS})

#
# Link with common
#
target_link_libraries(signing PRIVATE common)
target_link_libraries(signing PRIVATE ${Boost_LIBRARIES})
