#ifndef browser_h
#define browser_h

#include "SSL.h"

#include "browser_pac.h"

class Browser_Analyzer : public TCP_ApplicationAnalyzer {
public:

    bool ssl_est;

	Browser_Analyzer(Connection* conn);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Browser_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return orig_fin || orig_rst; }

    void PacketWithRST();

    void ConnectionClosed(TCP_Endpoint* endpoint,
    				    TCP_Endpoint* peer, int gen_event);

    void DeliverPacket(int len, const u_char* data,
                        bool is_orig, int seq, const IP_Hdr* ip, int caplen);

    const struct tcphdr* ExtractTCP_Header(const u_char*& data,
    					int& len, int& caplen);

private:
    unsigned int RST_cnt;
};

class Browser_SSL_Analyzer : public SSL_Analyzer {
public:
	Browser_SSL_Analyzer(Connection* conn, Browser_Analyzer* analyzer);

	static Analyzer* InstantiateAnalyzer(Connection* conn, Browser_Analyzer* analyzer)
		{ return new Browser_SSL_Analyzer(conn, analyzer); }

    void Established_SSL();

private:
    Browser_Analyzer * tcp_analyzer;
};

#endif
