/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TOPOLOGY_VIEW_H
#define TOPOLOGY_VIEW_H


#include <Point.h>
#include <String.h>
#include <View.h>

#include <vector>

class BMessage;


// A mesh-topology view of the current Tailscale tailnet: this device at the
// centre, each peer on a ring around it, with an edge coloured by send path
// (green = direct, amber = relay) and a node styled by state (filled = online,
// hollow = offline, ringed = exit-node capable, highlighted = the active exit
// node). It is a pure view of the peer array pushed via SetPeers(); clicking an
// exit-capable peer posts a kMsgExitNodeRequest to the host window (which
// forwards it to the daemon), and clicking the active exit node clears it.
class TopologyView : public BView {
public:
								TopologyView(const char* name);

			void				SetSelf(const char* name, const char* ip);
			void				SetPeers(const BMessage* data);

	virtual	void				Draw(BRect updateRect);
	virtual	void				MouseDown(BPoint where);
	virtual	void				MouseMoved(BPoint where, uint32 transit,
									const BMessage* drag);
	virtual	void				FrameResized(float w, float h);

private:
			struct PeerNode {
				BString		name;
				BString		ip;
				BString		nodeKey;
				bool		online;
				bool		exitCap;
				bool		exitOn;
				bool		direct;		// true = direct path, false = relay
				BPoint		pos;		// screen position, filled during Draw
			};

			int					_NodeAt(BPoint where) const;

			std::vector<PeerNode>	fPeers;
			BString				fSelfName;
			BString				fSelfIP;
			int					fHover;		// hovered node index, -1 = none
};


#endif	// TOPOLOGY_VIEW_H
