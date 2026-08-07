/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TOPOLOGY_WINDOW_H
#define TOPOLOGY_WINDOW_H


#include <Message.h>
#include <Messenger.h>
#include <String.h>
#include <Window.h>

class BButton;
class BMessageRunner;
class BStringView;
class TopologyView;


// A window hosting the live tailnet topology graph (TopologyView) plus an info
// panel. It polls the daemon for status about once a second (so byte counters,
// and thus the flow animation, stay live) and runs a faster timer that drives
// the animation. Clicking a peer in the graph fills the panel with its details;
// the panel's button routes traffic through that peer as an exit node (relayed
// to the parent, which owns the daemon connection).
class TopologyWindow : public BWindow {
public:
								TopologyWindow(BWindow* parent,
									BMessenger server);
	virtual						~TopologyWindow();

	virtual	void				MessageReceived(BMessage* message);

private:
			void				_ApplyData(const BMessage* data);
			void				_ShowPeerInfo(const char* nodeKey);
			void				_ClearInfo();
			void				_SetRow(int i, const char* label,
									const char* value);

			TopologyView*		fView;
			BMessenger			fParent;
			BMessenger			fServer;
			BMessageRunner*		fPollTimer;
			BMessageRunner*		fAnimTimer;
			BMessage			fLastStatus;	// for info-panel lookups
			BString				fSelectedKey;
			bool				fSelectedExitCap;
			bool				fSelectedExitOn;

			BStringView*		fInfoTitle;
			BStringView*		fInfoRows[6];
			BButton*			fExitButton;
};


#endif	// TOPOLOGY_WINDOW_H
