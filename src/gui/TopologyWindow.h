/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TOPOLOGY_WINDOW_H
#define TOPOLOGY_WINDOW_H


#include <Messenger.h>
#include <Window.h>

class TopologyView;


// A window hosting the tailnet topology graph (TopologyView). Like PeersWindow
// it is fed by MainWindow via kMsgPeersData; it also relays the view's
// exit-node clicks (kMsgExitNodeRequest) up to the parent, which forwards them
// to the daemon.
class TopologyWindow : public BWindow {
public:
								TopologyWindow(BWindow* parent);

	virtual	void				MessageReceived(BMessage* message);

private:
			TopologyView*		fView;
			BMessenger			fParent;
};


#endif	// TOPOLOGY_WINDOW_H
