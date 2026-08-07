/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TopologyWindow.h"

#include <LayoutBuilder.h>
#include <Message.h>

#include "PeersWindow.h"		// kMsgPeersData, kMsgExitNodeRequest
#include "TopologyView.h"
#include "VPNProtocol.h"


TopologyWindow::TopologyWindow(BWindow* parent)
	:
	BWindow(BRect(0, 0, 560, 520), "Tailnet map", B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE),
	fView(NULL),
	fParent(parent)
{
	fView = new TopologyView("topology");

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.SetInsets(0)
		.Add(fView);

	SetSizeLimits(360, 4000, 320, 4000);
	if (parent != NULL)
		CenterIn(parent->Frame());
	else
		CenterOnScreen();
}


void
TopologyWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgPeersData:
		{
			const char* selfIP = NULL;
			message->FindString(kFieldLocalIP, &selfIP);
			fView->SetSelf("this device", selfIP);
			fView->SetPeers(message);
			fView->Invalidate();
			break;
		}
		case kMsgExitNodeRequest:
			// Relay the view's exit-node click to the parent (MainWindow),
			// which owns the daemon connection.
			fParent.SendMessage(message);
			break;
		default:
			BWindow::MessageReceived(message);
			break;
	}
}
