/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "PeersWindow.h"

#include <Button.h>
#include <ColumnListView.h>
#include <ColumnTypes.h>
#include <LayoutBuilder.h>
#include <Message.h>
#include <String.h>

#include "VPNProtocol.h"


// Column indices. The node key rides an invisible column so a selected row
// carries the id the exit-node request needs, without cluttering the table.
enum {
	kColName	= 0,
	kColIP		= 1,
	kColPath	= 2,
	kColStatus	= 3,
	kColExit	= 4,
	kColNodeKey	= 5
};

// Button messages, handled inside the window.
static const uint32 kMsgUseExit		= 'gPuE';
static const uint32 kMsgStopExit	= 'gPsE';


PeersWindow::PeersWindow(BWindow* parent)
	:
	BWindow(BRect(0, 0, 520, 320), "Tailscale peers", B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE),
	fList(NULL),
	fUseExit(NULL),
	fStopExit(NULL),
	fParent(parent)
{
	fList = new BColumnListView("peerList", B_NAVIGABLE, B_FANCY_BORDER);
	fList->AddColumn(new BStringColumn("Machine", 150, 60, 400,
		B_TRUNCATE_MIDDLE), kColName);
	fList->AddColumn(new BStringColumn("Tailnet IP", 120, 80, 200,
		B_TRUNCATE_END), kColIP);
	fList->AddColumn(new BStringColumn("Path", 60, 50, 120,
		B_TRUNCATE_END), kColPath);
	fList->AddColumn(new BStringColumn("Status", 60, 50, 120,
		B_TRUNCATE_END), kColStatus);
	fList->AddColumn(new BStringColumn("Exit node", 90, 60, 160,
		B_TRUNCATE_END), kColExit);
	// Hidden carrier for the node key of the selected row.
	BStringColumn* keyCol = new BStringColumn("nodekey", 0, 0, 0,
		B_TRUNCATE_END);
	keyCol->SetVisible(false);
	fList->AddColumn(keyCol, kColNodeKey);

	fUseExit = new BButton("useExit", "Use as exit node",
		new BMessage(kMsgUseExit));
	fStopExit = new BButton("stopExit", "Stop exit node",
		new BMessage(kMsgStopExit));

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.SetInsets(-1)
		.Add(fList)
		.AddGroup(B_HORIZONTAL)
			.SetInsets(B_USE_WINDOW_SPACING, B_USE_SMALL_SPACING,
				B_USE_WINDOW_SPACING, B_USE_SMALL_SPACING)
			.Add(fUseExit)
			.Add(fStopExit)
			.AddGlue()
		.End();

	if (parent != NULL)
		CenterIn(parent->Frame());
	else
		CenterOnScreen();
}


void
PeersWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgPeersData:
			_Rebuild(message);
			break;
		case kMsgUseExit:
			_RequestExitNode(true);
			break;
		case kMsgStopExit:
			_RequestExitNode(false);
			break;
		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
PeersWindow::_RequestExitNode(bool use)
{
	BString key;
	if (use) {
		// Use the selected row's peer, if any and if it can be an exit node.
		BRow* row = fList->CurrentSelection(NULL);
		if (row == NULL)
			return;
		BStringField* exitField = dynamic_cast<BStringField*>(
			row->GetField(kColExit));
		if (exitField == NULL || BString(exitField->String()) == "\xe2\x80\x94")
			return;	// not exit-capable; ignore
		BStringField* keyField = dynamic_cast<BStringField*>(
			row->GetField(kColNodeKey));
		if (keyField == NULL)
			return;
		key = keyField->String();
		if (key.Length() == 0)
			return;
	}
	// Empty key clears the exit node. Forward to the parent (MainWindow), which
	// owns the daemon connection.
	BMessage req(kMsgExitNodeRequest);
	req.AddString(kFieldExitNodeKey, key);
	fParent.SendMessage(&req);
}


void
PeersWindow::_Rebuild(const BMessage* data)
{
	fList->Clear();

	BMessage peer;
	for (int32 i = 0; data->FindMessage(kFieldPeer, i, &peer) == B_OK; i++) {
		const char* name = NULL;
		const char* ip = NULL;
		const char* path = NULL;
		const char* nodeKey = NULL;
		bool online = false;
		bool exitCap = false;
		bool exitOn = false;
		peer.FindString(kFieldPeerName, &name);
		peer.FindString(kFieldPeerIP, &ip);
		peer.FindString(kFieldPeerPath, &path);
		peer.FindString(kFieldPeerNodeKey, &nodeKey);
		peer.FindBool(kFieldPeerOnline, &online);
		peer.FindBool(kFieldPeerExitCap, &exitCap);
		peer.FindBool(kFieldPeerExitOn, &exitOn);

		const char* exitLabel = "\xe2\x80\x94";		// em dash: not an exit node
		if (exitOn)
			exitLabel = "\xe2\x97\x8f active";		// black circle
		else if (exitCap)
			exitLabel = "available";

		BRow* row = new BRow();
		row->SetField(new BStringField(name != NULL ? name : "(unknown)"),
			kColName);
		row->SetField(new BStringField(ip != NULL && *ip != '\0'
			? ip : "\xe2\x80\x94"), kColIP);
		row->SetField(new BStringField(path != NULL ? path : "\xe2\x80\x94"),
			kColPath);
		row->SetField(new BStringField(online ? "online" : "offline"),
			kColStatus);
		row->SetField(new BStringField(exitLabel), kColExit);
		row->SetField(new BStringField(nodeKey != NULL ? nodeKey : ""),
			kColNodeKey);
		fList->AddRow(row);
	}
}
