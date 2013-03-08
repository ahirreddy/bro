#include "Browser.h"
#include "TCP_Reassembler.h"

Browser_Analyzer::Browser_Analyzer(Connection* c)
: SSL_Analyzer(c)
	{
		RST_cnt = 0;
	}

void Browser_Analyzer::PacketWithRST()
	{
		if ( TCP()->Orig()->RST_cnt > RST_cnt ) {
			RST_cnt = TCP()->Orig()->RST_cnt;
			Event(orig_rst);
		}

		TCP_ApplicationAnalyzer::PacketWithRST();
	}

void Browser_Analyzer::ConnectionClosed(TCP_Endpoint* endpoint,
				TCP_Endpoint* peer, int gen_event)
	{
		if ( endpoint->IsOrig() ) {
			Event(orig_fin);
		}

		TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);
	}

void Browser_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
		SSL_Analyzer::DeliverStream(len, data, orig);
	}

void Browser_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig,
					int seq, const IP_Hdr* ip, int caplen)
	{
		if (is_orig && interp->ssl_est()) {
			const struct tcphdr* tp = TCP_Analyzer::ExtractTCP_Header(data, len, caplen);
			TCP_Flags flags(tp);
			if ( !flags.SYN() && !flags.ACK() && !flags.RST() && !flags.RST() )
				cout << "This must be a data packet";
		}

		TCP_Analyzer::DeliverPacket(this, len, data, is_orig, seq, ip, caplen);
	}
