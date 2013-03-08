#include "OTCP.h"
#include "TCP_Reassembler.h"

OTCP_Analyzer::OTCP_Analyzer(Connection* c)
: TCP_ApplicationAnalyzer(AnalyzerTag::OTCP, c)
	{
		RST_cnt = 0;
	}

void OTCP_Analyzer::PacketWithRST()
	{
		if ( TCP()->Orig()->RST_cnt > RST_cnt ) {
			RST_cnt = TCP()->Orig()->RST_cnt;
			Event(orig_rst);
		}

		TCP_ApplicationAnalyzer::PacketWithRST();
	}

void OTCP_Analyzer::ConnectionClosed(TCP_Endpoint* endpoint,
				TCP_Endpoint* peer, int gen_event)
	{
		if ( endpoint->IsOrig() ) {
			Event(orig_fin);
		}

		TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);
	}
