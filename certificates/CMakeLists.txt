#
# Directories
#
set(CAS_CERTIFICATES_ROOT			${CAS_CERTIFICATES})

#
# Sources and headers
#
set(CAS_CERTIFICATES_SOURCE_FILES	${CAS_CERTIFICATES_ROOT}/main.cpp)

set(CAS_CERTIFICATES_HEADER_FILES	)

set(CAS_CERTIFICATES_SOURCES		${CAS_CERTIFICATES_SOURCE_FILES}
									${CAS_CERTIFICATES_HEADER_FILES})

#
# App itself
#
add_executable(certificates			${CAS_CERTIFICATES_SOURCES})

#
# Link with common
#
target_link_libraries(certificates PRIVATE common)
