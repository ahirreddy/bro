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
