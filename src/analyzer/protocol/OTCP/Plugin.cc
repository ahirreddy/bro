
#include "plugin/Plugin.h"

#include "OTCP.h"

BRO_PLUGIN_BEGIN(Bro, OTCP)
	BRO_PLUGIN_DESCRIPTION("OTCP analyzer");
	BRO_PLUGIN_ANALYZER("OTCP", otcp::OTCP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
