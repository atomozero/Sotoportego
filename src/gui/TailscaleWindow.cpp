/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TailscaleWindow.h"

#include <Alert.h>
#include <Button.h>
#include <LayoutBuilder.h>
#include <Message.h>
#include <String.h>
#include <StringView.h>
#include <TextControl.h>


const char* const kFieldTsName	= "soto:gui:tsname";
const char* const kFieldTsUrl	= "soto:gui:tsurl";

static const uint32 kMsgAdd		= 'twAd';
static const uint32 kMsgCancel	= 'twCa';

static const char* const kDefaultControlURL = "controlplane.tailscale.com";


TailscaleWindow::TailscaleWindow(BWindow* parent, const BMessenger& target,
	uint32 onOK)
	:
	BWindow(BRect(0, 0, 400, 200), "Add Tailscale network",
		B_MODAL_WINDOW_LOOK, B_MODAL_APP_WINDOW_FEEL,
		B_AUTO_UPDATE_SIZE_LIMITS | B_NOT_RESIZABLE | B_NOT_ZOOMABLE
			| B_CLOSE_ON_ESCAPE),
	fTarget(target),
	fOnOK(onOK),
	fNameField(NULL),
	fUrlField(NULL),
	fAddButton(NULL),
	fCancelButton(NULL)
{
	BStringView* heading = new BStringView("heading", "Join a Tailscale network");
	BFont bold(be_bold_font);
	heading->SetFont(&bold);

	BStringView* blurb = new BStringView("blurb",
		"You'll be sent to a browser to sign in after you connect.");

	fNameField = new BTextControl("name", "Name:", "my-tailnet", NULL);
	// The control server: the public coordination server by default; a Headscale
	// base URL (host or https://host) for self-hosted.
	fUrlField = new BTextControl("url", "Control server:",
		kDefaultControlURL, NULL);

	fAddButton = new BButton("add", "Add", new BMessage(kMsgAdd));
	fAddButton->MakeDefault(true);
	fCancelButton = new BButton("cancel", "Cancel", new BMessage(kMsgCancel));

	BLayoutBuilder::Group<>(this, B_VERTICAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_WINDOW_INSETS)
		.Add(heading)
		.Add(blurb)
		.Add(fNameField)
		.Add(fUrlField)
		.AddGroup(B_HORIZONTAL, B_USE_DEFAULT_SPACING)
			.AddGlue()
			.Add(fCancelButton)
			.Add(fAddButton)
		.End();

	if (parent != NULL)
		CenterIn(parent->Frame());
	else
		CenterOnScreen();

	fNameField->MakeFocus(true);
}


void
TailscaleWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgAdd:
		{
			BString name(fNameField->Text());
			name.Trim();
			if (name.Length() == 0) {
				BAlert* alert = new BAlert("noName",
					"Please give the network a name.", "OK");
				alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
				alert->Go();
				break;
			}
			BString url(fUrlField->Text());
			url.Trim();
			if (url.Length() == 0)
				url = kDefaultControlURL;

			BMessage reply(fOnOK);
			reply.AddString(kFieldTsName, name);
			reply.AddString(kFieldTsUrl, url);
			fTarget.SendMessage(&reply);
			PostMessage(B_QUIT_REQUESTED);
			break;
		}
		case kMsgCancel:
			PostMessage(B_QUIT_REQUESTED);
			break;
		default:
			BWindow::MessageReceived(message);
			break;
	}
}
