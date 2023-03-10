#
# Directories
#
set(CAS_CERT_REQUEST_ROOT			${CAS_CERTIFICATES}/request)
set(CAS_CERT_REQUEST_INCLUDE_DIRS	${CAS_CERTIFICATES_COMMON_INCLUDE})

#
# Sources and headers
#
set(CAS_CERT_REQUEST_SOURCE_FILES	${CAS_CERT_REQUEST_ROOT}/main.cpp)

set(CAS_CERT_REQUEST_HEADER_FILES	)

set(CAS_CERT_REQUEST_SOURCES		${CAS_CERT_REQUEST_SOURCE_FILES}
									${CAS_CERT_REQUEST_HEADER_FILES})

#
# App itself
#
add_executable(request				${CAS_CERT_REQUEST_SOURCES})

#
# Additional include directories
#
target_include_directories(request PRIVATE ${CAS_CERT_REQUEST_INCLUDE_DIRS})

#
# Link with common
#
target_link_libraries(request PRIVATE common)
