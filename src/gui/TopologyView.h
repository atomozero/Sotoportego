/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TOPOLOGY_VIEW_H
#define TOPOLOGY_VIEW_H


#include <Point.h>
#include <String.h>
#include <View.h>

#include <map>
#include <vector>

class BMessage;


// A live mesh-topology view of the current Tailscale tailnet: this device at the
// centre, each peer on a ring around it, with an edge coloured by send path
// (green = direct, amber = relay) and a node styled by state (filled = online,
// hollow = offline, ringed = exit-node capable, highlighted = the active exit
// node). When a peer is exchanging traffic, dots flow along its edge -- outward
// for bytes we send, inward for bytes we receive. Clicking a node selects it
// (the host window shows its details) and posts kMsgPeerSelected; the host drives
// exit-node changes from its info panel.
class TopologyView : public BView {
public:
								TopologyView(const char* name);

			void				SetSelf(const char* name, const char* ip);
			void				SetPeers(const BMessage* data);
			// Advance the flow animation one frame + decay activity; call from a
			// repaint timer. Invalidates only when something is moving.
			void				Pulse();
			void				SetSelected(const char* nodeKey);

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
				bool		direct;			// true = direct path, false = relay
				BPoint		pos;			// screen position, filled in Draw
			};
			// Per-peer flow state, persisted across SetPeers() rebuilds and keyed
			// by node key: last byte totals plus a decaying tx/rx activity level.
			struct Flow {
				uint64		tx;
				uint64		rx;
				float		txAct;
				float		rxAct;
				bool		seen;
				Flow() : tx(0), rx(0), txAct(0), rxAct(0), seen(false) {}
			};

			int					_NodeAt(BPoint where) const;
			void				_DrawFlow(BPoint a, BPoint b, float act,
									rgb_color col, bool inbound);

			std::vector<PeerNode>		fPeers;
			std::map<BString, Flow>		fFlow;
			BString				fSelfName;
			BString				fSelfIP;
			BString				fSelectedKey;
			int					fHover;			// hovered node index, -1 = none
			float				fPhase;			// flow animation phase 0..1
};


// Posted by TopologyView to its host window when a node is clicked; carries the
// peer's node key under kFieldPeerNodeKey ("" when the empty centre is clicked).
static const uint32 kMsgPeerSelected = 'gTsl';


#endif	// TOPOLOGY_VIEW_H
