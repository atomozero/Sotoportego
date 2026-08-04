/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "PeersWindow.h"

#include <ColumnListView.h>
#include <ColumnTypes.h>
#include <LayoutBuilder.h>
#include <Message.h>
#include <String.h>

#include "VPNProtocol.h"


PeersWindow::PeersWindow(BWindow* parent)
	:
	BWindow(BRect(0, 0, 460, 300), "Tailscale peers", B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE),
	fList(NULL)
{
	fList = new BColumnListView("peerList", B_NAVIGABLE, B_FANCY_BORDER);
	fList->AddColumn(new BStringColumn("Machine", 150, 60, 400,
		B_TRUNCATE_MIDDLE), 0);
	fList->AddColumn(new BStringColumn("Tailnet IP", 130, 80, 200,
		B_TRUNCATE_END), 1);
	fList->AddColumn(new BStringColumn("Path", 70, 50, 120,
		B_TRUNCATE_END), 2);
	fList->AddColumn(new BStringColumn("Status", 70, 50, 120,
		B_TRUNCATE_END), 3);

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.SetInsets(-1)
		.Add(fList);

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
		default:
			BWindow::MessageReceived(message);
			break;
	}
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
		bool online = false;
		peer.FindString(kFieldPeerName, &name);
		peer.FindString(kFieldPeerIP, &ip);
		peer.FindString(kFieldPeerPath, &path);
		peer.FindBool(kFieldPeerOnline, &online);

		BRow* row = new BRow();
		row->SetField(new BStringField(name != NULL ? name : "(unknown)"), 0);
		row->SetField(new BStringField(ip != NULL && *ip != '\0'
			? ip : "\xe2\x80\x94"), 1);
		row->SetField(new BStringField(path != NULL ? path : "\xe2\x80\x94"), 2);
		row->SetField(new BStringField(online ? "online" : "offline"), 3);
		fList->AddRow(row);
	}
}
