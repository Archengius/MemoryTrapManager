cmake_minimum_required(VERSION 3.0)
project(MemoryTrapTest)

set(CMAKE_CXX_STANDARD 23)

# Whenever to build a shared library. By default, static library will be built
if(NOT DEFINED MTM_BUILD_SHARED)
    set(MTM_BUILD_SHARED 0)
endif()

# Decide library type depending on the settings
if (${MTM_BUILD_SHARED} MATCHES 1)
    set(MTM_LIBRARY_TYPE SHARED)
elseif()
    set(MTM_LIBRARY_TYPE STATIC)
endif()

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/zydis zydis EXCLUDE_FROM_ALL)
include_directories(${CMAKE_CURRENT_LIST_DIR}/include)

# Add the library to the target
add_library(MemoryTrapManager ${MTM_LIBRARY_TYPE} src/MemoryTrapManager.cpp)
target_link_libraries(MemoryTrapManager PRIVATE Zydis)

# Add extra compile definitions when building shared library
if (${MTM_BUILD_SHARED} MATCHES 1)
    target_compile_definitions(MemoryTrapManager PUBLIC MTM_SHARED)
    target_compile_definitions(MemoryTrapManager PRIVATE BUILDING_MTM)
endif()

# Add test executable to the targets
add_executable(MemoryTrapTest src/MemoryManagerTest.cpp)
target_link_libraries(MemoryTrapTest PRIVATE MemoryTrapManager)
