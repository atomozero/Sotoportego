/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef VPN_STATS_H
#define VPN_STATS_H


#include <SupportDefs.h>
#include <time.h>

class BMessage;


// Lightweight counters describing an active (or last) VPN session. Values are
// cumulative for the lifetime of the current connection and reset on connect.
class VPNStats {
public:
								VPNStats();

			void				Reset();

	// Serialize/deserialize into a flat BMessage (used for IPC). Fields are
	// added with the kField* names declared in VPNProtocol.h.
			status_t			Archive(BMessage* into) const;
			status_t			Unarchive(const BMessage& from);

			int64				fBytesIn;
			int64				fBytesOut;
	// Wall-clock time the tunnel reached the Connected state, or 0 if never
	// connected during this session.
			time_t				fConnectedSince;
};


#endif	// VPN_STATS_H
