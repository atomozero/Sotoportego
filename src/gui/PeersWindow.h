/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef PEERS_WINDOW_H
#define PEERS_WINDOW_H


#include <Window.h>

class BColumnListView;


// A live list of the Tailscale peers on the current tailnet: machine name,
// tailnet IPv4, send path (direct or relay) and online status. The window is a
// pure view of data pushed by MainWindow: it receives a kMsgPeersData message
// (carrying one kFieldPeer sub-message per peer) whenever a status update
// arrives, and rebuilds its table from it.
class PeersWindow : public BWindow {
public:
								PeersWindow(BWindow* parent);

	virtual	void				MessageReceived(BMessage* message);

private:
			void				_Rebuild(const BMessage* data);

			BColumnListView*	fList;
};


// Sent by MainWindow to a PeersWindow with the latest peer array attached
// (repeated kFieldPeer sub-messages).
static const uint32 kMsgPeersData = 'gPwD';


#endif	// PEERS_WINDOW_H
