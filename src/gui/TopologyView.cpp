/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TopologyView.h"

#include <math.h>
#include <string.h>

#include <Font.h>
#include <Message.h>
#include <Window.h>

#include "PeersWindow.h"		// kMsgExitNodeRequest
#include "VPNProtocol.h"


// Palette.
static const rgb_color kColDirect	= { 46, 204, 113, 255 };	// green
static const rgb_color kColRelay	= { 230, 126, 34, 255 };	// amber
static const rgb_color kColOffline	= { 170, 170, 170, 255 };	// grey
static const rgb_color kColSelf		= { 41, 128, 185, 255 };	// blue
static const rgb_color kColExit		= { 142, 68, 173, 255 };	// purple
static const rgb_color kColExitRing	= { 200, 170, 220, 255 };	// faint purple
static const rgb_color kColText		= { 40, 40, 40, 255 };
static const rgb_color kColBg		= { 246, 247, 249, 255 };

static const float kSelfRadius	= 13.0f;
static const float kNodeRadius	= 9.0f;
static const float kHitRadius	= 16.0f;


TopologyView::TopologyView(const char* name)
	:
	BView(name, B_WILL_DRAW | B_FRAME_EVENTS | B_FULL_UPDATE_ON_RESIZE),
	fSelfName("this device"),
	fSelfIP(""),
	fHover(-1)
{
	SetViewColor(kColBg);
}


void
TopologyView::SetSelf(const char* name, const char* ip)
{
	fSelfName = (name != NULL && *name != '\0') ? name : "this device";
	fSelfIP = (ip != NULL) ? ip : "";
}


void
TopologyView::SetPeers(const BMessage* data)
{
	fPeers.clear();
	fHover = -1;

	BMessage peer;
	for (int32 i = 0; data->FindMessage(kFieldPeer, i, &peer) == B_OK; i++) {
		PeerNode n;
		const char* s = NULL;
		if (peer.FindString(kFieldPeerName, &s) == B_OK && s != NULL)
			n.name = s;
		if (peer.FindString(kFieldPeerIP, &s) == B_OK && s != NULL)
			n.ip = s;
		if (peer.FindString(kFieldPeerNodeKey, &s) == B_OK && s != NULL)
			n.nodeKey = s;
		const char* path = NULL;
		peer.FindString(kFieldPeerPath, &path);
		n.direct = (path != NULL && strcmp(path, "direct") == 0);
		n.online = false;
		n.exitCap = false;
		n.exitOn = false;
		peer.FindBool(kFieldPeerOnline, &n.online);
		peer.FindBool(kFieldPeerExitCap, &n.exitCap);
		peer.FindBool(kFieldPeerExitOn, &n.exitOn);
		n.pos = BPoint(0, 0);
		fPeers.push_back(n);
	}
}


int
TopologyView::_NodeAt(BPoint where) const
{
	for (size_t i = 0; i < fPeers.size(); i++) {
		BPoint p = fPeers[i].pos;
		float dx = p.x - where.x;
		float dy = p.y - where.y;
		if (dx * dx + dy * dy <= kHitRadius * kHitRadius)
			return (int)i;
	}
	return -1;
}


void
TopologyView::Draw(BRect updateRect)
{
	BRect b = Bounds();
	BPoint center((b.left + b.right) / 2, (b.top + b.bottom) / 2);
	float margin = 76.0f;
	float radius = (b.Width() < b.Height() ? b.Width() : b.Height()) / 2
		- margin;
	if (radius < 40.0f)
		radius = 40.0f;

	BFont bold(be_bold_font);
	bold.SetSize(10.0f);
	BFont plain(be_plain_font);
	plain.SetSize(9.0f);

	// Position peers on a ring, starting at the top and going clockwise.
	size_t n = fPeers.size();
	for (size_t i = 0; i < n; i++) {
		double a = -M_PI / 2 + 2 * M_PI * (double)i / (double)(n > 0 ? n : 1);
		fPeers[i].pos = BPoint(center.x + radius * (float)cos(a),
			center.y + radius * (float)sin(a));
	}

	// Edges first, so nodes sit on top of them.
	for (size_t i = 0; i < n; i++) {
		const PeerNode& p = fPeers[i];
		rgb_color edge = !p.online ? kColOffline
			: (p.direct ? kColDirect : kColRelay);
		SetHighColor(edge);
		SetPenSize(p.exitOn ? 3.0f : (p.online ? 2.0f : 1.0f));
		StrokeLine(center, p.pos);
	}
	SetPenSize(1.0f);

	// Peer nodes + labels.
	SetFont(&bold);
	for (size_t i = 0; i < n; i++) {
		const PeerNode& p = fPeers[i];
		bool hot = ((int)i == fHover);

		// Exit-node ring (outer) for capable peers; thicker/purple if active.
		if (p.exitCap) {
			SetHighColor(p.exitOn ? kColExit : kColExitRing);
			SetPenSize(p.exitOn ? 3.0f : 2.0f);
			StrokeEllipse(p.pos, kNodeRadius + 4, kNodeRadius + 4);
			SetPenSize(1.0f);
		}

		rgb_color fill = !p.online ? kColOffline
			: (p.direct ? kColDirect : kColRelay);
		if (p.online) {
			SetHighColor(fill);
			FillEllipse(p.pos, kNodeRadius + (hot ? 2 : 0),
				kNodeRadius + (hot ? 2 : 0));
		} else {
			// Offline: hollow ring.
			SetHighColor(kColBg);
			FillEllipse(p.pos, kNodeRadius, kNodeRadius);
			SetHighColor(kColOffline);
			StrokeEllipse(p.pos, kNodeRadius, kNodeRadius);
		}

		// Labels: name, then IP, centred under the node.
		const char* name = p.name.Length() > 0 ? p.name.String() : "(unknown)";
		SetFont(&bold);
		SetHighColor(kColText);
		float nw = StringWidth(name);
		DrawString(name, BPoint(p.pos.x - nw / 2,
			p.pos.y + kNodeRadius + 14));
		if (p.ip.Length() > 0) {
			SetFont(&plain);
			SetHighColor(90, 90, 90);
			float iw = StringWidth(p.ip.String());
			DrawString(p.ip.String(), BPoint(p.pos.x - iw / 2,
				p.pos.y + kNodeRadius + 26));
			SetFont(&bold);
		}
	}

	// Self node in the centre.
	SetHighColor(kColSelf);
	FillEllipse(center, kSelfRadius, kSelfRadius);
	SetHighColor(255, 255, 255);
	SetFont(&bold);
	{
		const char* label = fSelfName.String();
		float lw = StringWidth(label);
		SetHighColor(kColText);
		DrawString(label, BPoint(center.x - lw / 2,
			center.y + kSelfRadius + 14));
		if (fSelfIP.Length() > 0) {
			SetFont(&plain);
			SetHighColor(90, 90, 90);
			float iw = StringWidth(fSelfIP.String());
			DrawString(fSelfIP.String(), BPoint(center.x - iw / 2,
				center.y + kSelfRadius + 26));
		}
	}

	// Empty state.
	if (n == 0) {
		SetFont(&plain);
		SetHighColor(120, 120, 120);
		const char* msg = "No peers on this tailnet";
		float mw = StringWidth(msg);
		DrawString(msg, BPoint(center.x - mw / 2, b.bottom - 40));
	}

	// Legend.
	SetFont(&plain);
	float ly = b.bottom - 14;
	float lx = b.left + 14;
	struct { rgb_color c; const char* t; } legend[] = {
		{ kColDirect, "direct" },
		{ kColRelay, "relay" },
		{ kColOffline, "offline" },
		{ kColExit, "exit node" }
	};
	for (int i = 0; i < 4; i++) {
		SetHighColor(legend[i].c);
		FillEllipse(BPoint(lx + 4, ly - 3), 4, 4);
		SetHighColor(kColText);
		DrawString(legend[i].t, BPoint(lx + 12, ly));
		lx += 16 + StringWidth(legend[i].t) + 14;
	}
}


void
TopologyView::MouseDown(BPoint where)
{
	int idx = _NodeAt(where);
	if (idx < 0)
		return;
	const PeerNode& p = fPeers[idx];
	if (!p.exitCap)
		return;

	// Toggle: if this peer is the active exit node, clear it; else select it.
	BMessage req(kMsgExitNodeRequest);
	req.AddString(kFieldExitNodeKey, p.exitOn ? BString("") : p.nodeKey);
	if (Window() != NULL)
		Window()->PostMessage(&req);
}


void
TopologyView::MouseMoved(BPoint where, uint32 transit, const BMessage* drag)
{
	int idx = (transit == B_EXITED_VIEW) ? -1 : _NodeAt(where);
	if (idx != fHover) {
		fHover = idx;
		Invalidate();
	}
}


void
TopologyView::FrameResized(float w, float h)
{
	BView::FrameResized(w, h);
	Invalidate();
}
