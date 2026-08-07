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

#include "VPNProtocol.h"


// Palette.
static const rgb_color kColDirect	= { 46, 204, 113, 255 };	// green
static const rgb_color kColRelay	= { 230, 126, 34, 255 };	// amber
static const rgb_color kColOffline	= { 176, 182, 189, 255 };	// grey
static const rgb_color kColSelf		= { 41, 128, 185, 255 };	// blue
static const rgb_color kColExit		= { 142, 68, 173, 255 };	// purple
static const rgb_color kColExitRing	= { 205, 178, 224, 255 };	// faint purple
static const rgb_color kColSelRing	= { 52, 152, 219, 255 };	// selection blue
static const rgb_color kColText		= { 44, 52, 60, 255 };
static const rgb_color kColSub		= { 120, 128, 136, 255 };
static const rgb_color kColBg		= { 248, 249, 251, 255 };
static const rgb_color kColWhite	= { 255, 255, 255, 255 };

static const float kSelfRadius	= 15.0f;
static const float kNodeRadius	= 9.0f;
static const float kHitRadius	= 18.0f;


static rgb_color
mix(rgb_color a, rgb_color b, float t)
{
	rgb_color c;
	c.red   = (uint8)(a.red   + (b.red   - a.red)   * t);
	c.green = (uint8)(a.green + (b.green - a.green) * t);
	c.blue  = (uint8)(a.blue  + (b.blue  - a.blue)  * t);
	c.alpha = 255;
	return c;
}


TopologyView::TopologyView(const char* name)
	:
	BView(name, B_WILL_DRAW | B_FRAME_EVENTS | B_FULL_UPDATE_ON_RESIZE),
	fSelfName("this device"),
	fSelfIP(""),
	fSelectedKey(""),
	fHover(-1),
	fPhase(0.0f)
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

		// Byte totals drive the flow animation: a rise since the last snapshot
		// lights the edge in that direction.
		int64 tx = 0, rx = 0;
		peer.FindInt64(kFieldPeerTx, &tx);
		peer.FindInt64(kFieldPeerRx, &rx);
		Flow& f = fFlow[n.nodeKey];
		if (f.seen) {
			if ((uint64)tx > f.tx)
				f.txAct = 1.0f;
			if ((uint64)rx > f.rx)
				f.rxAct = 1.0f;
		}
		f.tx = (uint64)tx;
		f.rx = (uint64)rx;
		f.seen = true;

		fPeers.push_back(n);
	}
}


void
TopologyView::SetSelected(const char* nodeKey)
{
	fSelectedKey = (nodeKey != NULL) ? nodeKey : "";
	Invalidate();
}


void
TopologyView::Pulse()
{
	fPhase += 0.045f;
	if (fPhase >= 1.0f)
		fPhase -= 1.0f;

	bool active = false;
	for (std::map<BString, Flow>::iterator it = fFlow.begin();
			it != fFlow.end(); ++it) {
		it->second.txAct *= 0.90f;
		it->second.rxAct *= 0.90f;
		if (it->second.txAct > 0.03f || it->second.rxAct > 0.03f)
			active = true;
	}
	if (active)
		Invalidate();
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
TopologyView::_DrawFlow(BPoint a, BPoint b, float act, rgb_color col,
	bool inbound)
{
	if (act < 0.04f)
		return;
	const int kDots = 4;
	SetDrawingMode(B_OP_ALPHA);
	SetBlendingMode(B_CONSTANT_ALPHA, B_ALPHA_OVERLAY);
	for (int i = 0; i < kDots; i++) {
		float base = fPhase + (float)i / kDots;
		base -= floorf(base);
		float t = inbound ? (1.0f - base) : base;
		t = 0.14f + t * 0.72f;	// keep dots off the node/label zones
		BPoint p(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t);
		uint8 alpha = (uint8)(act * 230);
		rgb_color c = col;
		c.alpha = alpha;
		SetHighColor(c);
		float r = 2.4f + act * 1.8f;
		FillEllipse(p, r, r);
	}
	SetDrawingMode(B_OP_COPY);
}


void
TopologyView::Draw(BRect updateRect)
{
	BRect b = Bounds();
	BPoint center((b.left + b.right) / 2, (b.top + b.bottom) / 2);
	float margin = 82.0f;
	float radius = (b.Width() < b.Height() ? b.Width() : b.Height()) / 2
		- margin;
	if (radius < 46.0f)
		radius = 46.0f;

	BFont bold(be_bold_font);
	bold.SetSize(10.0f);
	BFont plain(be_plain_font);
	plain.SetSize(9.0f);

	size_t n = fPeers.size();
	for (size_t i = 0; i < n; i++) {
		double a = -M_PI / 2 + 2 * M_PI * (double)i / (double)(n > 0 ? n : 1);
		fPeers[i].pos = BPoint(center.x + radius * (float)cos(a),
			center.y + radius * (float)sin(a));
	}

	// Base edges (thin, muted) so the mesh is visible even with no traffic.
	SetDrawingMode(B_OP_COPY);
	for (size_t i = 0; i < n; i++) {
		const PeerNode& p = fPeers[i];
		rgb_color base = !p.online ? kColOffline
			: (p.direct ? kColDirect : kColRelay);
		SetHighColor(mix(base, kColBg, 0.55f));
		SetPenSize(p.exitOn ? 2.5f : 1.4f);
		StrokeLine(center, p.pos);
	}
	SetPenSize(1.0f);

	// Animated traffic flow on top of the base edges.
	for (size_t i = 0; i < n; i++) {
		const PeerNode& p = fPeers[i];
		if (!p.online)
			continue;
		rgb_color col = p.direct ? kColDirect : kColRelay;
		const Flow& f = fFlow[p.nodeKey];
		_DrawFlow(center, p.pos, f.txAct, col, false);	// outbound
		_DrawFlow(center, p.pos, f.rxAct, mix(col, kColSelf, 0.35f), true);
	}

	// Peer nodes + labels.
	for (size_t i = 0; i < n; i++) {
		const PeerNode& p = fPeers[i];
		bool hot = ((int)i == fHover);
		bool sel = (p.nodeKey.Length() > 0 && p.nodeKey == fSelectedKey);
		float nr = kNodeRadius + (hot ? 2.0f : 0.0f);

		// Selection ring.
		if (sel) {
			SetHighColor(kColSelRing);
			SetPenSize(2.5f);
			StrokeEllipse(p.pos, nr + 6, nr + 6);
			SetPenSize(1.0f);
		}
		// Exit-node ring.
		if (p.exitCap) {
			SetHighColor(p.exitOn ? kColExit : kColExitRing);
			SetPenSize(p.exitOn ? 3.0f : 2.0f);
			StrokeEllipse(p.pos, nr + 4, nr + 4);
			SetPenSize(1.0f);
		}

		// Soft drop shadow.
		SetDrawingMode(B_OP_ALPHA);
		SetBlendingMode(B_CONSTANT_ALPHA, B_ALPHA_OVERLAY);
		SetHighColor(0, 0, 0, 38);
		FillEllipse(BPoint(p.pos.x, p.pos.y + 2), nr, nr);
		SetDrawingMode(B_OP_COPY);

		rgb_color fill = !p.online ? kColOffline
			: (p.direct ? kColDirect : kColRelay);
		if (p.online) {
			SetHighColor(fill);
			FillEllipse(p.pos, nr, nr);
			SetHighColor(mix(fill, kColWhite, 0.35f));
			FillEllipse(BPoint(p.pos.x - nr * 0.28f, p.pos.y - nr * 0.28f),
				nr * 0.4f, nr * 0.4f);	// tiny highlight
		} else {
			SetHighColor(255, 255, 255);
			FillEllipse(p.pos, nr, nr);
			SetHighColor(kColOffline);
			SetPenSize(1.5f);
			StrokeEllipse(p.pos, nr, nr);
			SetPenSize(1.0f);
		}

		// Labels.
		const char* name = p.name.Length() > 0 ? p.name.String() : "(unknown)";
		SetFont(&bold);
		SetHighColor(kColText);
		float nw = StringWidth(name);
		DrawString(name, BPoint(p.pos.x - nw / 2, p.pos.y + nr + 15));
		if (p.ip.Length() > 0) {
			SetFont(&plain);
			SetHighColor(kColSub);
			float iw = StringWidth(p.ip.String());
			DrawString(p.ip.String(), BPoint(p.pos.x - iw / 2,
				p.pos.y + nr + 27));
		}
	}

	// Self node in the centre (with a subtle outer ring).
	SetHighColor(mix(kColSelf, kColBg, 0.7f));
	SetPenSize(2.0f);
	StrokeEllipse(center, kSelfRadius + 5, kSelfRadius + 5);
	SetPenSize(1.0f);
	SetDrawingMode(B_OP_ALPHA);
	SetBlendingMode(B_CONSTANT_ALPHA, B_ALPHA_OVERLAY);
	SetHighColor(0, 0, 0, 45);
	FillEllipse(BPoint(center.x, center.y + 2), kSelfRadius, kSelfRadius);
	SetDrawingMode(B_OP_COPY);
	SetHighColor(kColSelf);
	FillEllipse(center, kSelfRadius, kSelfRadius);
	SetHighColor(mix(kColSelf, kColWhite, 0.4f));
	FillEllipse(BPoint(center.x - 4, center.y - 4), 5, 5);

	SetFont(&bold);
	SetHighColor(kColText);
	{
		float lw = StringWidth(fSelfName.String());
		DrawString(fSelfName.String(), BPoint(center.x - lw / 2,
			center.y + kSelfRadius + 16));
		if (fSelfIP.Length() > 0) {
			SetFont(&plain);
			SetHighColor(kColSub);
			float iw = StringWidth(fSelfIP.String());
			DrawString(fSelfIP.String(), BPoint(center.x - iw / 2,
				center.y + kSelfRadius + 28));
		}
	}

	// Empty state.
	if (n == 0) {
		SetFont(&plain);
		SetHighColor(kColSub);
		const char* msg = "No peers on this tailnet";
		float mw = StringWidth(msg);
		DrawString(msg, BPoint(center.x - mw / 2, b.bottom - 44));
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
	BMessage sel(kMsgPeerSelected);
	if (idx >= 0) {
		fSelectedKey = fPeers[idx].nodeKey;
		sel.AddString(kFieldPeerNodeKey, fPeers[idx].nodeKey);
	} else {
		fSelectedKey = "";
	}
	Invalidate();
	if (Window() != NULL)
		Window()->PostMessage(&sel);
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
