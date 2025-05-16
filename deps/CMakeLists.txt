# buxn
add_library(buxn INTERFACE)
target_include_directories(buxn INTERFACE "buxn/include")

add_library(buxn-vm STATIC "buxn/src/vm/vm.c")
target_link_libraries(buxn-vm PUBLIC buxn)

add_library(buxn-dbg-core STATIC "buxn/src/dbg/core.c")
target_link_libraries(buxn-dbg-core PUBLIC buxn blibs)

add_library(buxn-dbg-protocol STATIC "buxn/src/dbg/protocol.c")
target_link_libraries(buxn-dbg-protocol PUBLIC buxn blibs)

include(bio/deps/CMakeLists.txt)
SET(BUILD_DEPS OFF CACHE BOOL "bio should not build deps")
add_subdirectory(bio EXCLUDE_FROM_ALL)
