#ifndef otcp_h
#define otcp_h

#include "SSL.h"

#include "otcp_pac.h"

class OTCP_Analyzer : public TCP_ApplicationAnalyzer {
public:
	OTCP_Analyzer(Connection* conn);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new OTCP_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return orig_fin || orig_rst; }

    void PacketWithRST();

    void ConnectionClosed(TCP_Endpoint* endpoint,
    				    TCP_Endpoint* peer, int gen_event);

private:
    unsigned int RST_cnt;
};

#endif
