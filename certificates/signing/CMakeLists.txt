#
# Directories
#
set(CAS_SIGNING_ROOT			${CAS_CERTIFICATES}/request)

#
# Sources and headers
#
set(CAS_SIGNING_SOURCE_FILES	${CAS_SIGNING_ROOT}/main.cpp)

set(CAS_SIGNING_HEADER_FILES	)

set(CAS_SIGNING_SOURCES			${CAS_SIGNING_SOURCE_FILES}
								${CAS_SIGNING_HEADER_FILES})

#
# App itself
#
add_executable(signing				${CAS_SIGNING_SOURCES})

#
# Link with common
#
target_link_libraries(signing PRIVATE common)
