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
			const struct tcphdr* tp = ExtractTCP_Header(data, len, caplen);
			TCP_Flags flags(tp);
			if ( !flags.SYN() && !flags.ACK() && !flags.RST() && !flags.RST() )
				cout << "This must be a data packet";
		}

		SSL_Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
	}

const struct tcphdr* Browser_Analyzer::ExtractTCP_Header(const u_char*& data,
					int& len, int& caplen)
	{
	const struct tcphdr* tp = (const struct tcphdr*) data;
	uint32 tcp_hdr_len = tp->th_off * 4;

	if ( tcp_hdr_len < sizeof(struct tcphdr) )
		{
		//Weird("bad_TCP_header_len");
		return 0;
		}

	if ( tcp_hdr_len > uint32(len) ||
	     sizeof(struct tcphdr) > uint32(caplen) )
		{
		// This can happen even with the above test, due to TCP
		// options.
		//Weird("truncated_header");
		return 0;
		}

	len -= tcp_hdr_len;	// remove TCP header
	caplen -= tcp_hdr_len;
	data += tcp_hdr_len;

	return tp;
	}
