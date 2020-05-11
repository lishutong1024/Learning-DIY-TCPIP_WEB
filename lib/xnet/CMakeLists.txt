include_directories(
        ${PROJECT_SOURCE_DIR}/xnet/src/xnet/inc
)

aux_source_directory(. DIR_HELLO_SRCS)
add_library(xnet_lib  ${DIR_HELLO_SRCS} )
