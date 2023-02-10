#
# provider-params depends on Boost.Program_options
#
find_package(Boost COMPONENTS program_options REQUIRED)

#
# Directories
#
set(CAS_PROVPARAMS_ROOT			${CAS_CRYPTOPROVIDERS}/provider-params)
set(CAS_PROVPARAMS_INCLUDE_DIRS	${Boost_INCLUDE_DIR})

#
# Sources and headers
#
set(CAS_PROVPARAMS_SOURCE_FILES	${CAS_PROVPARAMS_ROOT}/main.cpp)

set(CAS_PROVPARAMS_HEADER_FILES	)

set(CAS_PROVPARAMS_SOURCES		${CAS_PROVPARAMS_SOURCE_FILES}
								${CAS_PROVPARAMS_HEADER_FILES})

#
# App itself
#
add_executable(provider-params		${CAS_PROVPARAMS_SOURCES})

#
# Additional include directories
#
target_include_directories(provider-params PRIVATE ${CAS_PROVPARAMS_INCLUDE_DIRS})

#
# Link with common
#
target_link_libraries(provider-params PRIVATE common)
target_link_libraries(provider-params PRIVATE ${Boost_LIBRARIES})
