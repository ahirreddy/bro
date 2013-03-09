#ifndef browser_h
#define browser_h

#include "SSL.h"

#include "browser_pac.h"

class Browser_Analyzer : public SSL_Analyzer {
public:
	Browser_Analyzer(Connection* conn);
	virtual ~Browser_Analyzer();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Browser_Analyzer(conn); }

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
