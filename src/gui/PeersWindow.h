/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef PEERS_WINDOW_H
#define PEERS_WINDOW_H


#include <Messenger.h>
#include <Window.h>

class BButton;
class BColumnListView;


// A live list of the Tailscale peers on the current tailnet: machine name,
// tailnet IPv4, send path (direct or relay), online status and exit-node role.
// The window is a mostly-passive view of data pushed by MainWindow (a
// kMsgPeersData message carrying one kFieldPeer sub-message per peer), but it can
// also drive exit-node selection: the "Use as exit node" / "Stop exit node"
// buttons post a kMsgExitNodeRequest back to the parent (MainWindow), which
// forwards it to the daemon.
class PeersWindow : public BWindow {
public:
								PeersWindow(BWindow* parent);

	virtual	void				MessageReceived(BMessage* message);

private:
			void				_Rebuild(const BMessage* data);
			void				_RequestExitNode(bool use);

			BColumnListView*	fList;
			BButton*			fUseExit;
			BButton*			fStopExit;
			BMessenger			fParent;
};


// Sent by MainWindow to a PeersWindow with the latest peer array attached
// (repeated kFieldPeer sub-messages).
static const uint32 kMsgPeersData = 'gPwD';

// Sent by PeersWindow to its parent (MainWindow) to (de)select an exit node.
// Carries kFieldExitNodeKey (the peer's node key hex, or empty to clear).
static const uint32 kMsgExitNodeRequest = 'gPxN';


#endif	// PEERS_WINDOW_H
