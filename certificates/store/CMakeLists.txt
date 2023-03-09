#
# Directories
#
set(CAS_CERT_STORE_ROOT			${CAS_CERTIFICATES}/store)

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
# Link with common
#
target_link_libraries(store PRIVATE common)
