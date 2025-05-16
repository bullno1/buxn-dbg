set(SOURCES
	"main.c"
)
add_executable(buxn-dbg ${SOURCES})
target_link_libraries(buxn-dbg PRIVATE bio)
