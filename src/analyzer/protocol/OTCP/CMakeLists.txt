
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro OTCP)
bro_plugin_cc(OTCP.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(otcp.pac otcp-analyzer.pac otcp-protocol.pac)
bro_plugin_end()
