#
# enum-providers depends on Boost.Program_options
#
find_package(Boost COMPONENTS program_options REQUIRED)

#
# Directories
#
set(CAS_ENUM_PROVIDERS_ROOT			${CAS_CRYPTOPROVIDERS}/enum-providers)
set(CAS_ENUM_PROVIDERS_INCLUDE_DIRS ${Boost_INCLUDE_DIR})

#
# Sources and headers
#
set(CAS_ENUM_PROVIDERS_SOURCE_FILES	${CAS_ENUM_PROVIDERS_ROOT}/main.cpp)

set(CAS_ENUM_PROVIDERS_HEADER_FILES	)

set(CAS_ENUM_PROVIDERS_SOURCES		${CAS_ENUM_PROVIDERS_SOURCE_FILES}
									${CAS_ENUM_PROVIDERS_HEADER_FILES})

#
# App itself
#
add_executable(enum-providers		${CAS_ENUM_PROVIDERS_SOURCES})

#
# Additional include directories
#
target_include_directories(enum-providers PRIVATE ${CAS_ENUM_PROVIDERS_INCLUDE_DIRS})

#
# Link with common
#
target_link_libraries(enum-providers PRIVATE common)
target_link_libraries(enum-providers PRIVATE ${Boost_LIBRARIES})
