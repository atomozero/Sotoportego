/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef MAGIC_SOCK_H
#define MAGIC_SOCK_H


#include <stddef.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <SupportDefs.h>


// magicsock: the single UDP socket that carries all of Tailscale's peer traffic,
// multiplexing several protocols by inspecting the first bytes of each datagram.
// One socket serves three roles at once:
//   * STUN  -- responses from a DERP server's STUN service tell us our public
//              ip:port (the endpoints we advertise to control);
//   * disco -- NaCl-boxed ping/pong the peers exchange to find a direct path;
//   * WireGuard -- everything else is a real encrypted transport packet handed
//              to the WireGuard data plane.
//
// This revision provides the socket (bind/send/recv) and the inbound classifier;
// the reader thread, STUN sweep, disco probing and per-peer path selection layer
// on top as the data plane is wired in.
namespace ts {

enum SockPacketKind {
	PKT_WIREGUARD	= 0,	// default: hand to the WG transport
	PKT_STUN		= 1,
	PKT_DISCO		= 2
};


class MagicSock {
public:
								MagicSock();
								~MagicSock();

			// Open a UDP socket bound to `port` (0 picks an ephemeral port).
			// Sets a receive timeout so the reader loop can poll a stop flag.
			status_t			Open(uint16 port);
			void				Close();

			bool				IsOpen() const { return fSocket >= 0; }
			int					Fd() const { return fSocket; }
			uint16				LocalPort() const { return fPort; }

			// Send `len` bytes to `to`. Returns bytes sent or -1.
			ssize_t				SendTo(const struct sockaddr* to,
									socklen_t toLen, const void* buf, size_t len);

			// Receive one datagram (blocking, bounded by the recv timeout).
			// Fills `from` if non-NULL. Returns bytes received, 0/-1 on
			// timeout/error.
			ssize_t				Recv(void* buf, size_t cap,
									struct sockaddr_storage* from,
									socklen_t* fromLen);

			// Classify an inbound datagram by its leading bytes.
	static	SockPacketKind		Classify(const uint8* buf, size_t len);

private:
			int					fSocket;
			uint16				fPort;
};

}	// namespace ts


#endif	// MAGIC_SOCK_H
