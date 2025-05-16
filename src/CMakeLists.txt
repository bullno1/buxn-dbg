set(SOURCES
	"main.c"
	"cmd.c"
	"cmd_help.c"
)
add_executable(buxn-dbg ${SOURCES})
target_link_libraries(
	buxn-dbg
	PRIVATE
	bio
	blibs
	buxn-dbg-core
	buxn-dbg-protocol
)
