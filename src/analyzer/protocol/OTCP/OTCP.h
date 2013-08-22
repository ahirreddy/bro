#ifndef otcp_h
#define otcp_h

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"
#include "otcp_pac.h"

namespace analyzer { namespace otcp {

class OTCP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	OTCP_Analyzer(Connection* conn);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new OTCP_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return orig_fin || orig_rst; }

    void PacketWithRST();

    void ConnectionClosed(tcp::TCP_Endpoint* endpoint,
    				    tcp::TCP_Endpoint* peer, int gen_event);

private:
    unsigned int RST_cnt;
};

} } // namespace analyzer::*

#endif
