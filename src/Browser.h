#ifndef browser_h
#define browser_h

#include "SSL.h"

#include "browser_pac.h"

class Browser_Analyzer : public TCP_ApplicationAnalyzer {
public:
	Browser_Analyzer(Connection* conn);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Browser_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return orig_fin || orig_rst; }

    virtual void PacketWithRST();

    virtual void Browser_Analyzer::ConnectionClosed(TCP_Endpoint* endpoint,
    				    TCP_Endpoint* peer, int gen_event);

private:
    unsigned int RST_cnt;
};

class Browser_SSL_Analyzer : public SSL_Analyzer {
public:
	Browser_SSL_Analyzer(Connection* conn);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Browser_SSL_Analyzer(conn); }

    virtual void Browser_SSL_Analyzer::DeliverStream(int len, const u_char* data,
                        bool orig);

    virtual void Browser_SSL_Analyzer::DeliverPacket(int len, const u_char* data,
                        bool is_orig, int seq, const IP_Hdr* ip, int caplen);

    virtual const struct tcphdr* Browser_SSL_Analyzer::ExtractTCP_Header(const u_char*& data,
    					int& len, int& caplen);
};

#endif
