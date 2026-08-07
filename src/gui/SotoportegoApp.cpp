/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "SotoportegoApp.h"

#include <string.h>

#include <PropertyInfo.h>

#include "AboutWindow.h"
#include "MainWindow.h"
#include "VPNProtocol.h"


// Scripting suite: two executable properties that map onto the connect and
// disconnect paths. Reachable as `hey Sotoportego Connect` / `Disconnect`.
static property_info sPropertyList[] = {
	{
		const_cast<char*>("Connect"),
		{ B_EXECUTE_PROPERTY, 0 },
		{ B_DIRECT_SPECIFIER, 0 },
		const_cast<char*>("Connect the selected VPN profile."),
		0, {}, {}, {}
	},
	{
		const_cast<char*>("Disconnect"),
		{ B_EXECUTE_PROPERTY, 0 },
		{ B_DIRECT_SPECIFIER, 0 },
		const_cast<char*>("Disconnect the active VPN session."),
		0, {}, {}, {}
	},
	{ 0, { 0 }, { 0 }, 0, 0, {}, {}, {} }
};


SotoportegoApp::SotoportegoApp()
	:
	BApplication(kGUISignature),
	fWindow(NULL)
{
}


void
SotoportegoApp::ReadyToRun()
{
	fWindow = new MainWindow();
	fWindow->Show();
}


void
SotoportegoApp::AboutRequested()
{
	(new AboutWindow())->Show();
}


status_t
SotoportegoApp::GetSupportedSuites(BMessage* data)
{
	data->AddString("suites", "suite/vnd.atomozero-Sotoportego");
	BPropertyInfo info(sPropertyList);
	data->AddFlat("messages", &info);
	return BApplication::GetSupportedSuites(data);
}


BHandler*
SotoportegoApp::ResolveSpecifier(BMessage* message, int32 index,
	BMessage* specifier, int32 what, const char* property)
{
	BPropertyInfo info(sPropertyList);
	if (info.FindMatch(message, index, specifier, what, property) >= 0)
		return this;
	return BApplication::ResolveSpecifier(message, index, specifier, what,
		property);
}


void
SotoportegoApp::MessageReceived(BMessage* message)
{
	if (message->what == B_EXECUTE_PROPERTY) {
		const char* property = NULL;
		if (message->GetCurrentSpecifier(NULL, NULL, NULL, &property) == B_OK
				&& property != NULL && fWindow != NULL) {
			uint32 action = 0;
			if (strcmp(property, "Connect") == 0)
				action = kMsgAutomationConnect;
			else if (strcmp(property, "Disconnect") == 0)
				action = kMsgAutomationDisconnect;
			if (action != 0) {
				fWindow->PostMessage(action);
				BMessage reply(B_REPLY);
				reply.AddInt32("error", B_OK);
				message->SendReply(&reply);
				return;
			}
		}
	}
	BApplication::MessageReceived(message);
}
