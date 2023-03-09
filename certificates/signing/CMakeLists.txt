#
# Directories
#
set(CAS_CERT_SIGNING_ROOT			${CAS_CERTIFICATES}/request)

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
# Link with common
#
target_link_libraries(signing PRIVATE common)
