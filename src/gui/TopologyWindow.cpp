/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TopologyWindow.h"

#include <stdio.h>

#include <Button.h>
#include <Font.h>
#include <GroupLayout.h>
#include <GroupView.h>
#include <LayoutBuilder.h>
#include <MessageRunner.h>
#include <Size.h>
#include <StringView.h>

#include "PeersWindow.h"		// kMsgPeersData, kMsgExitNodeRequest
#include "TopologyView.h"
#include "VPNProtocol.h"


// Timers + panel actions.
static const uint32 kMsgPollTick	= 'gTpk';	// request fresh status
static const uint32 kMsgAnimTick	= 'gTan';	// advance the flow animation
static const uint32 kMsgUseExit		= 'gTue';	// info-panel exit-node button


static BString
human_bytes(int64 n)
{
	BString s;
	double v = (double)n;
	if (n < 1024)
		s.SetToFormat("%lld B", (long long)n);
	else if (n < 1024 * 1024)
		s.SetToFormat("%.1f KB", v / 1024.0);
	else if (n < 1024LL * 1024 * 1024)
		s.SetToFormat("%.1f MB", v / (1024.0 * 1024.0));
	else
		s.SetToFormat("%.2f GB", v / (1024.0 * 1024.0 * 1024.0));
	return s;
}


TopologyWindow::TopologyWindow(BWindow* parent, BMessenger server)
	:
	BWindow(BRect(0, 0, 760, 540), "Tailnet map", B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE),
	fView(NULL),
	fParent(parent),
	fServer(server),
	fPollTimer(NULL),
	fAnimTimer(NULL),
	fSelectedKey(""),
	fSelectedExitCap(false),
	fSelectedExitOn(false),
	fInfoTitle(NULL),
	fExitButton(NULL)
{
	fView = new TopologyView("topology");

	fInfoTitle = new BStringView("title", "Select a peer");
	BFont bold(be_bold_font);
	fInfoTitle->SetFont(&bold);
	for (int i = 0; i < 6; i++)
		fInfoRows[i] = new BStringView("row", "");
	fExitButton = new BButton("exit", "Use as exit node",
		new BMessage(kMsgUseExit));
	fExitButton->SetEnabled(false);

	BGroupView* panel = new BGroupView(B_VERTICAL, 0);
	BLayoutBuilder::Group<>(panel->GroupLayout())
		.SetInsets(B_USE_WINDOW_SPACING, B_USE_WINDOW_SPACING,
			B_USE_WINDOW_SPACING, B_USE_WINDOW_SPACING)
		.Add(fInfoTitle)
		.AddStrut(6)
		.Add(fInfoRows[0])
		.Add(fInfoRows[1])
		.Add(fInfoRows[2])
		.Add(fInfoRows[3])
		.Add(fInfoRows[4])
		.Add(fInfoRows[5])
		.AddGlue()
		.Add(fExitButton)
		.End();
	panel->SetExplicitMinSize(BSize(210, B_SIZE_UNSET));
	panel->SetExplicitMaxSize(BSize(250, B_SIZE_UNLIMITED));

	BLayoutBuilder::Group<>(this, B_HORIZONTAL, 0)
		.Add(fView)
		.Add(panel)
		.End();

	SetSizeLimits(480, 4000, 340, 4000);
	_ClearInfo();

	if (parent != NULL)
		CenterIn(parent->Frame());
	else
		CenterOnScreen();

	// Poll the daemon ~1 Hz for fresh byte counters, and animate ~15 fps.
	if (fServer.IsValid()) {
		BMessage poll(kMsgPollTick);
		fPollTimer = new BMessageRunner(BMessenger(this), &poll, 1000000, -1);
	}
	BMessage anim(kMsgAnimTick);
	fAnimTimer = new BMessageRunner(BMessenger(this), &anim, 66000, -1);
}


TopologyWindow::~TopologyWindow()
{
	delete fPollTimer;
	delete fAnimTimer;
}


void
TopologyWindow::_SetRow(int i, const char* label, const char* value)
{
	if (i < 0 || i >= 6)
		return;
	BString s;
	if (value != NULL && *value != '\0')
		s.SetToFormat("%s  %s", label, value);
	else
		s = "";
	fInfoRows[i]->SetText(s.String());
}


void
TopologyWindow::_ClearInfo()
{
	fInfoTitle->SetText("Select a peer");
	for (int i = 0; i < 6; i++)
		fInfoRows[i]->SetText("");
	fSelectedExitCap = false;
	fSelectedExitOn = false;
	fExitButton->SetEnabled(false);
	fExitButton->SetLabel("Use as exit node");
}


void
TopologyWindow::_ApplyData(const BMessage* data)
{
	fLastStatus = *data;
	const char* selfIP = NULL;
	data->FindString(kFieldLocalIP, &selfIP);
	fView->SetSelf("this device", selfIP);
	fView->SetPeers(data);
	fView->Invalidate();
	if (fSelectedKey.Length() > 0)
		_ShowPeerInfo(fSelectedKey.String());
}


void
TopologyWindow::_ShowPeerInfo(const char* nodeKey)
{
	BMessage peer;
	for (int32 i = 0;
			fLastStatus.FindMessage(kFieldPeer, i, &peer) == B_OK; i++) {
		const char* key = NULL;
		peer.FindString(kFieldPeerNodeKey, &key);
		if (key == NULL || strcmp(key, nodeKey) != 0)
			continue;

		const char* name = NULL;
		const char* ip = NULL;
		const char* path = NULL;
		const char* endpoint = NULL;
		const char* derpCode = NULL;
		bool online = false, exitCap = false, exitOn = false;
		int64 tx = 0, rx = 0;
		int32 hsAge = -1, derp = -1;
		peer.FindString(kFieldPeerName, &name);
		peer.FindString(kFieldPeerIP, &ip);
		peer.FindString(kFieldPeerPath, &path);
		peer.FindString(kFieldPeerEndpoint, &endpoint);
		peer.FindString(kFieldPeerDerpCode, &derpCode);
		peer.FindBool(kFieldPeerOnline, &online);
		peer.FindBool(kFieldPeerExitCap, &exitCap);
		peer.FindBool(kFieldPeerExitOn, &exitOn);
		peer.FindInt64(kFieldPeerTx, &tx);
		peer.FindInt64(kFieldPeerRx, &rx);
		peer.FindInt32(kFieldPeerHsAge, &hsAge);
		peer.FindInt32(kFieldPeerDerp, &derp);

		fInfoTitle->SetText(name != NULL && *name != '\0' ? name : "(unknown)");
		_SetRow(0, "Tailnet IP", ip != NULL ? ip : "\xe2\x80\x94");
		_SetRow(1, "Status", online ? "online" : "offline");

		BString pathStr(path != NULL ? path : "\xe2\x80\x94");
		if (path != NULL && strcmp(path, "direct") == 0 && endpoint != NULL
				&& *endpoint != '\0')
			pathStr.SetToFormat("direct \xe2\x80\x94 %s", endpoint);
		else if (path != NULL && strcmp(path, "relay") == 0) {
			if (derpCode != NULL && *derpCode != '\0')
				pathStr.SetToFormat("relay via %s", derpCode);
			else if (derp > 0)
				pathStr.SetToFormat("relay (region %d)", (int)derp);
		}
		_SetRow(2, "Path", pathStr.String());

		BString hs;
		if (hsAge < 0)
			hs = "\xe2\x80\x94";
		else if (hsAge < 60)
			hs.SetToFormat("%ds ago", (int)hsAge);
		else
			hs.SetToFormat("%dm %ds ago", (int)hsAge / 60, (int)hsAge % 60);
		_SetRow(3, "Handshake", hs.String());

		_SetRow(4, "Sent", human_bytes(tx).String());
		_SetRow(5, "Received", human_bytes(rx).String());

		fSelectedExitCap = exitCap;
		fSelectedExitOn = exitOn;
		fExitButton->SetEnabled(exitCap);
		fExitButton->SetLabel(exitOn ? "Stop exit node" : "Use as exit node");
		return;
	}
	// Peer no longer present.
	_ClearInfo();
}


void
TopologyWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgPeersData:
		case kMsgStatusUpdate:
			_ApplyData(message);
			break;

		case kMsgPollTick:
		{
			if (!fServer.IsValid())
				break;
			BMessage req(kMsgGetStatus);
			req.AddMessenger(kFieldClient, BMessenger(this));
			fServer.SendMessage(&req);
			break;
		}

		case kMsgAnimTick:
			fView->Pulse();
			break;

		case kMsgPeerSelected:
		{
			const char* key = NULL;
			if (message->FindString(kFieldPeerNodeKey, &key) == B_OK
					&& key != NULL && *key != '\0') {
				fSelectedKey = key;
				_ShowPeerInfo(key);
			} else {
				fSelectedKey = "";
				_ClearInfo();
			}
			break;
		}

		case kMsgUseExit:
		{
			if (fSelectedKey.Length() == 0)
				break;
			BMessage req(kMsgExitNodeRequest);
			req.AddString(kFieldExitNodeKey,
				fSelectedExitOn ? BString("") : fSelectedKey);
			fParent.SendMessage(&req);
			break;
		}

		default:
			BWindow::MessageReceived(message);
			break;
	}
}
