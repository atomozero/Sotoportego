/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H


#include <Messenger.h>
#include <String.h>
#include <Window.h>

#include "VPNState.h"

class BButton;
class BListView;
class BStringView;
class HeaderView;


// The main Sotoportego window. Like the CLI, it is purely a client of the
// daemon: it subscribes over BMessage, reflects the broadcast state/stats, and
// sends connect/disconnect requests. No VPN logic lives here.
//
// Visual layout, top to bottom:
//   * BMenuBar
//   * HeaderView (slate banner, brand tile + status dot + metadata)
//   * BTabView ("Connection" / "Statistics")
//   * status BStringView (compact bottom line)
class MainWindow : public BWindow {
public:
								MainWindow();

	virtual	void				MessageReceived(BMessage* message);

private:
			void				_BuildLayout();
			BView*				_BuildConnectionTab();
			BView*				_BuildStatisticsTab();
			void				_EnsureSubscribed();
			void				_SendConnect();
			void				_SendDisconnect();
			void				_UpdateForState(VPNState state,
									const char* detail);
			void				_ApplyStats(const BMessage* message);
			void				_AppendEvent(const char* text);

	static	BString				_FormatBytes(int64 bytes);

			BMessenger			fServer;
			VPNState			fState;

			HeaderView*			fHeader;
			BStringView*		fServerLabel;
			BStringView*		fBackendLabel;
			BStringView*		fSinceValue;
			BStringView*		fDownValue;
			BStringView*		fUpValue;
			BListView*			fProfileList;
			BListView*			fEventLog;
			BButton*			fActionButton;
			BStringView*		fStatusBar;
};


#endif	// MAIN_WINDOW_H
