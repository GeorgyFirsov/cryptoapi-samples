#
# Directories
#
set(CAS_ENUM_TYPES_ROOT			${CAS_CRYPTOPROVIDERS}/enum-provider-types)

#
# Sources and headers
#
set(CAS_ENUM_TYPES_SOURCE_FILES	${CAS_ENUM_TYPES_ROOT}/main.cpp)

set(CAS_ENUM_TYPES_HEADER_FILES	)

set(CAS_ENUM_TYPES_SOURCES		${CAS_ENUM_TYPES_SOURCE_FILES}
								${CAS_ENUM_TYPES_HEADER_FILES})

#
# App itself
#
add_executable(enum-provider-types	${CAS_ENUM_TYPES_SOURCES})

#
# Link with common
#
target_link_libraries(enum-provider-types PRIVATE common)
