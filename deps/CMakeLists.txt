# termbox2
add_library(termbox2 INTERFACE)
target_include_directories(termbox2 INTERFACE "termbox2")

# utf8proc
add_library(utf8proc STATIC "utf8proc/utf8proc.c")
target_include_directories(utf8proc PUBLIC "utf8proc")

# buxn
add_library(buxn INTERFACE)
target_include_directories(buxn INTERFACE "buxn/include")

add_library(buxn-vm STATIC "buxn/src/vm/vm.c")
target_link_libraries(buxn-vm PUBLIC buxn)

add_library(buxn-dbg-core STATIC "buxn/src/dbg/core.c")
target_link_libraries(buxn-dbg-core PUBLIC buxn)

add_library(buxn-dbg-protocol STATIC "buxn/src/dbg/protocol.c")
target_link_libraries(buxn-dbg-protocol PUBLIC buxn blibs)

add_library(buxn-dbg-symtab STATIC "buxn/src/dbg/symtab.c")
target_link_libraries(buxn-dbg-symtab PUBLIC buxn blibs)

add_library(buxn-dbg-transport-stream STATIC "buxn/src/dbg/transports/stream.c")
target_link_libraries(buxn-dbg-transport-stream PUBLIC buxn)

include(bio/deps/CMakeLists.txt)
SET(BUILD_DEPS OFF CACHE BOOL "bio should not build deps")
add_subdirectory(bio EXCLUDE_FROM_ALL)
