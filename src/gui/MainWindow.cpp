/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "MainWindow.h"

#include <stdio.h>
#include <time.h>

#include <Application.h>
#include <Box.h>
#include <Button.h>
#include <Font.h>
#include <GroupLayout.h>
#include <LayoutBuilder.h>
#include <ListItem.h>
#include <ListView.h>
#include <Menu.h>
#include <MenuBar.h>
#include <MenuItem.h>
#include <Message.h>
#include <OS.h>
#include <Roster.h>
#include <ScrollView.h>
#include <StringView.h>
#include <TabView.h>
#include <View.h>

#include "HeaderView.h"
#include "VPNProfile.h"
#include "VPNProtocol.h"
#include "VPNStats.h"


// GUI-private message codes.
static const uint32 kMsgPrimaryAction	= 'gAct';
static const uint32 kMsgConnectAction	= 'gCon';
static const uint32 kMsgDisconnectAction = 'gDis';

// Demo profile values, used until profile editing/import lands.
static const char* const kDemoProfileName	= "Demo Profile";
static const char* const kDemoServerHost	= "vpn.example.com";
static const uint16 kDemoServerPort			= 1194;
static const char* const kDemoBackendName	= "OpenVPN";


MainWindow::MainWindow()
	:
	BWindow(BRect(100, 100, 720, 560), "Sotoportego", B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS | B_QUIT_ON_WINDOW_CLOSE),
	fServer(),
	fState(VPN_STATE_DISCONNECTED),
	fHeader(NULL),
	fServerLabel(NULL),
	fBackendLabel(NULL),
	fSinceValue(NULL),
	fDownValue(NULL),
	fUpValue(NULL),
	fProfileList(NULL),
	fEventLog(NULL),
	fActionButton(NULL),
	fStatusBar(NULL)
{
	_BuildLayout();
	_UpdateForState(VPN_STATE_DISCONNECTED, NULL);
	_EnsureSubscribed();
}


void
MainWindow::_BuildLayout()
{
	BMenuBar* menuBar = new BMenuBar("menubar");

	BMenu* appMenu = new BMenu("App");
	appMenu->AddItem(new BMenuItem("About Sotoportego" B_UTF8_ELLIPSIS,
		new BMessage(B_ABOUT_REQUESTED)));
	appMenu->AddSeparatorItem();
	appMenu->AddItem(new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED), 'Q'));
	menuBar->AddItem(appMenu);

	BMenu* connectionMenu = new BMenu("Connection");
	connectionMenu->AddItem(new BMenuItem("Connect",
		new BMessage(kMsgConnectAction)));
	connectionMenu->AddItem(new BMenuItem("Disconnect",
		new BMessage(kMsgDisconnectAction)));
	menuBar->AddItem(connectionMenu);

	fHeader = new HeaderView("header");

	BTabView* tabs = new BTabView("tabs", B_WIDTH_FROM_LABEL);
	tabs->AddTab(_BuildConnectionTab());
	tabs->AddTab(_BuildStatisticsTab());
	tabs->TabAt(0)->SetLabel("Connection");
	tabs->TabAt(1)->SetLabel("Statistics");

	fStatusBar = new BStringView("statusBar", "Disconnected");
	BFont smallFont(be_plain_font);
	smallFont.SetSize(smallFont.Size() * 0.9f);
	fStatusBar->SetFont(&smallFont);

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.Add(menuBar)
		.Add(fHeader)
		.AddGroup(B_VERTICAL, B_USE_DEFAULT_SPACING)
			.SetInsets(B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING,
				B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING)
			.Add(tabs)
		.End()
		.AddGroup(B_HORIZONTAL, 0)
			.SetInsets(B_USE_WINDOW_INSETS, 0,
				B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING)
			.Add(fStatusBar)
			.AddGlue()
		.End();
}


BView*
MainWindow::_BuildConnectionTab()
{
	BView* tab = new BView("connectionTab", B_WILL_DRAW);
	tab->SetViewUIColor(B_PANEL_BACKGROUND_COLOR);

	// --- Left column: profile list -----------------------------------------
	BBox* profilesBox = new BBox("profilesBox");
	profilesBox->SetLabel("Profiles");

	fProfileList = new BListView("profileList");
	fProfileList->AddItem(new BStringItem(kDemoProfileName));
	fProfileList->Select(0);
	BScrollView* listScroll = new BScrollView("profileScroll", fProfileList,
		0, false, true);

	BButton* addButton = new BButton("addProfile", "+", NULL);
	BButton* removeButton = new BButton("removeProfile", "\xe2\x80\x93", NULL);
	addButton->SetEnabled(false);
	removeButton->SetEnabled(false);

	BLayoutBuilder::Group<>(profilesBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(listScroll)
		.AddGroup(B_HORIZONTAL, B_USE_SMALL_SPACING)
			.Add(addButton)
			.Add(removeButton)
			.AddGlue()
		.End();

	// --- Right column: server details + action -----------------------------
	BBox* detailsBox = new BBox("detailsBox");
	detailsBox->SetLabel("Server");

	char serverBuf[128];
	snprintf(serverBuf, sizeof(serverBuf), "%s:%u", kDemoServerHost,
		(unsigned)kDemoServerPort);
	fServerLabel = new BStringView("serverLabel", serverBuf);
	BFont bigFont(be_bold_font);
	bigFont.SetSize(bigFont.Size() * 1.2f);
	fServerLabel->SetFont(&bigFont);

	fBackendLabel = new BStringView("backendLabel", kDemoBackendName);

	BLayoutBuilder::Group<>(detailsBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(new BStringView("serverCaption", "Host"))
		.Add(fServerLabel)
		.Add(new BStringView("backendCaption", "Backend"))
		.Add(fBackendLabel)
		.AddGlue();

	fActionButton = new BButton("actionButton", "Connect",
		new BMessage(kMsgPrimaryAction));
	fActionButton->MakeDefault(true);

	BLayoutBuilder::Group<>(tab, B_VERTICAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING)
		.AddGroup(B_HORIZONTAL, B_USE_DEFAULT_SPACING)
			.Add(profilesBox, 0.40f)
			.Add(detailsBox, 0.60f)
		.End()
		.AddGroup(B_HORIZONTAL, 0)
			.AddGlue()
			.Add(fActionButton)
		.End();

	return tab;
}


BView*
MainWindow::_BuildStatisticsTab()
{
	BView* tab = new BView("statisticsTab", B_WILL_DRAW);
	tab->SetViewUIColor(B_PANEL_BACKGROUND_COLOR);

	// --- Session summary (left) --------------------------------------------
	BBox* sessionBox = new BBox("sessionBox");
	sessionBox->SetLabel("Session");

	fSinceValue = new BStringView("sinceValue", "\xe2\x80\x94");
	fDownValue = new BStringView("downValue", "0 B");
	fUpValue = new BStringView("upValue", "0 B");

	BFont monoFont(be_fixed_font);
	fSinceValue->SetFont(&monoFont);
	fDownValue->SetFont(&monoFont);
	fUpValue->SetFont(&monoFont);

	BLayoutBuilder::Grid<>(sessionBox, B_USE_DEFAULT_SPACING,
			B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(new BStringView("sinceLabel", "Since"), 0, 0)
		.Add(fSinceValue, 1, 0)
		.Add(new BStringView("downLabel", "Download"), 0, 1)
		.Add(fDownValue, 1, 1)
		.Add(new BStringView("upLabel", "Upload"), 0, 2)
		.Add(fUpValue, 1, 2);

	// --- Event log (right) -------------------------------------------------
	BBox* eventsBox = new BBox("eventsBox");
	eventsBox->SetLabel("Events");

	fEventLog = new BListView("eventLog");
	fEventLog->SetFont(&monoFont);
	BScrollView* eventScroll = new BScrollView("eventScroll", fEventLog,
		0, false, true);

	BLayoutBuilder::Group<>(eventsBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(eventScroll);

	BLayoutBuilder::Group<>(tab, B_HORIZONTAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING)
		.Add(sessionBox, 0.40f)
		.Add(eventsBox, 0.60f);

	return tab;
}


void
MainWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgPrimaryAction:
			// The primary button means connect when idle, disconnect otherwise.
			if (fState == VPN_STATE_DISCONNECTED || fState == VPN_STATE_ERROR)
				_SendConnect();
			else
				_SendDisconnect();
			break;

		case kMsgConnectAction:
			_SendConnect();
			break;
		case kMsgDisconnectAction:
			_SendDisconnect();
			break;

		case B_ABOUT_REQUESTED:
			be_app->PostMessage(B_ABOUT_REQUESTED);
			break;

		case kMsgStatusUpdate:
		{
			int32 state = VPN_STATE_DISCONNECTED;
			message->FindInt32(kFieldState, &state);
			const char* detail = NULL;
			if (message->FindString(kFieldDetail, &detail) != B_OK)
				detail = NULL;
			_UpdateForState((VPNState)state, detail);
			_ApplyStats(message);
			break;
		}

		case kMsgStatsUpdate:
			_ApplyStats(message);
			break;

		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
MainWindow::_EnsureSubscribed()
{
	// Launch the daemon if needed, then subscribe and pull the current status.
	if (be_roster->Launch(kServerSignature) != B_OK
			&& be_roster->Launch(kServerSignature) != B_ALREADY_RUNNING) {
		// Best effort; the messenger check below decides whether we proceed.
	}

	for (int attempt = 0; attempt < 30; attempt++) {
		fServer = BMessenger(kServerSignature);
		if (fServer.IsValid())
			break;
		snooze(100000);
	}

	if (!fServer.IsValid())
		return;

	BMessage subscribe(kMsgSubscribe);
	subscribe.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&subscribe);

	BMessage status(kMsgGetStatus);
	status.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&status);
}


void
MainWindow::_SendConnect()
{
	if (!fServer.IsValid())
		return;

	// TODO: build this from the selected VPNProfile once profile management and
	// .ovpn parsing land; for now it mirrors the CLI's demo profile.
	VPNProfile profile;
	profile.fBackendType = VPN_BACKEND_OPENVPN;
	profile.fName = kDemoProfileName;
	profile.fServer = kDemoServerHost;
	profile.fPort = kDemoServerPort;
	profile.fUsername = "demo";

	BMessage archive;
	profile.Archive(&archive);

	BMessage connect(kMsgConnect);
	connect.AddMessenger(kFieldClient, BMessenger(this));
	connect.AddMessage(kFieldProfile, &archive);
	fServer.SendMessage(&connect);
}


void
MainWindow::_SendDisconnect()
{
	if (!fServer.IsValid())
		return;

	BMessage disconnect(kMsgDisconnect);
	disconnect.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&disconnect);
}


void
MainWindow::_UpdateForState(VPNState state, const char* detail)
{
	VPNState previous = fState;
	fState = state;

	const char* action = (state == VPN_STATE_DISCONNECTED
		|| state == VPN_STATE_ERROR) ? "Connect" : "Disconnect";

	if (fHeader != NULL) {
		fHeader->SetState(state);

		BString subtitle(vpn_state_name(state));
		if (detail != NULL && detail[0] != '\0') {
			subtitle << " \xc2\xb7 ";
			subtitle << detail;
		} else if (state != VPN_STATE_DISCONNECTED) {
			char serverBuf[128];
			snprintf(serverBuf, sizeof(serverBuf), "%s:%u",
				kDemoServerHost, (unsigned)kDemoServerPort);
			subtitle << " \xc2\xb7 ";
			subtitle << serverBuf;
		}
		fHeader->SetSubtitle(subtitle.String());
	}

	if (fActionButton != NULL)
		fActionButton->SetLabel(action);

	if (fStatusBar != NULL) {
		BString status;
		status << "1 profile \xc2\xb7 ";
		status << vpn_state_name(state);
		fStatusBar->SetText(status.String());
	}

	if (previous != state) {
		BString line(vpn_state_name(state));
		if (detail != NULL && detail[0] != '\0') {
			line << " \xe2\x80\x94 ";
			line << detail;
		}
		_AppendEvent(line.String());
	}
}


void
MainWindow::_ApplyStats(const BMessage* message)
{
	VPNStats stats;
	stats.Unarchive(*message);

	if (fDownValue != NULL)
		fDownValue->SetText(_FormatBytes(stats.fBytesIn).String());
	if (fUpValue != NULL)
		fUpValue->SetText(_FormatBytes(stats.fBytesOut).String());

	if (fSinceValue != NULL) {
		if (stats.fConnectedSince > 0) {
			char buffer[32];
			struct tm local;
			time_t when = stats.fConnectedSince;
			localtime_r(&when, &local);
			strftime(buffer, sizeof(buffer), "%H:%M:%S", &local);
			fSinceValue->SetText(buffer);
		} else {
			fSinceValue->SetText("\xe2\x80\x94");
		}
	}
}


void
MainWindow::_AppendEvent(const char* text)
{
	if (fEventLog == NULL || text == NULL)
		return;

	char timeBuf[16];
	time_t now = time(NULL);
	struct tm local;
	localtime_r(&now, &local);
	strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &local);

	BString line;
	line << timeBuf << "  " << text;
	fEventLog->AddItem(new BStringItem(line.String()));
	fEventLog->ScrollToSelection();

	int32 count = fEventLog->CountItems();
	if (count > 0)
		fEventLog->Select(count - 1);
}


BString
MainWindow::_FormatBytes(int64 bytes)
{
	const char* units[] = { "B", "KB", "MB", "GB", "TB" };
	double value = (double)bytes;
	int unit = 0;
	while (value >= 1024.0 && unit < 4) {
		value /= 1024.0;
		unit++;
	}

	char buffer[48];
	if (unit == 0)
		snprintf(buffer, sizeof(buffer), "%lld B", (long long)bytes);
	else
		snprintf(buffer, sizeof(buffer), "%.1f %s", value, units[unit]);

	return BString(buffer);
}
