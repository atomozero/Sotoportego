/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "CredentialsWindow.h"

#include <Button.h>
#include <LayoutBuilder.h>
#include <Message.h>
#include <StringView.h>
#include <TextControl.h>
#include <TextView.h>

#include "VPNProtocol.h"


static const uint32 kMsgOK		= 'cwOK';
static const uint32 kMsgCancel	= 'cwCa';


CredentialsWindow::CredentialsWindow(BWindow* parent, const BMessenger& target,
	uint32 onOK, uint32 onCancel, const char* profileName,
	const BString& prefilledUser)
	:
	BWindow(BRect(0, 0, 360, 180), "Credentials",
		B_MODAL_WINDOW_LOOK, B_MODAL_APP_WINDOW_FEEL,
		B_AUTO_UPDATE_SIZE_LIMITS | B_NOT_RESIZABLE | B_NOT_ZOOMABLE
			| B_CLOSE_ON_ESCAPE),
	fTarget(target),
	fOnOK(onOK),
	fOnCancel(onCancel),
	fUserField(NULL),
	fPasswordField(NULL),
	fOKButton(NULL),
	fCancelButton(NULL),
	fSent(false)
{
	BString prompt("Sign in to ");
	prompt << (profileName != NULL && profileName[0] != '\0'
		? profileName : "the VPN");
	BStringView* promptView = new BStringView("prompt", prompt.String());
	BFont bold(be_bold_font);
	promptView->SetFont(&bold);

	fUserField = new BTextControl("user", "Username:", prefilledUser.String(),
		NULL);
	fPasswordField = new BTextControl("password", "Password:", "", NULL);
	// Mask the password as the user types.
	if (fPasswordField->TextView() != NULL)
		fPasswordField->TextView()->HideTyping(true);

	fOKButton = new BButton("ok", "Connect", new BMessage(kMsgOK));
	fOKButton->MakeDefault(true);
	fCancelButton = new BButton("cancel", "Cancel",
		new BMessage(kMsgCancel));

	BLayoutBuilder::Group<>(this, B_VERTICAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_WINDOW_INSETS)
		.Add(promptView)
		.Add(fUserField)
		.Add(fPasswordField)
		.AddGroup(B_HORIZONTAL, B_USE_DEFAULT_SPACING)
			.AddGlue()
			.Add(fCancelButton)
			.Add(fOKButton)
		.End();

	if (parent != NULL)
		CenterIn(parent->Frame());
	else
		CenterOnScreen();

	// Put the cursor where the user is likely to type next.
	if (prefilledUser.Length() == 0)
		fUserField->MakeFocus(true);
	else
		fPasswordField->MakeFocus(true);
}


void
CredentialsWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgOK:
		{
			BMessage reply(fOnOK);
			reply.AddString(kFieldUsername, fUserField->Text());
			reply.AddString(kFieldPassword, fPasswordField->Text());
			fTarget.SendMessage(&reply);
			fSent = true;
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


bool
CredentialsWindow::QuitRequested()
{
	if (!fSent) {
		BMessage cancel(fOnCancel);
		fTarget.SendMessage(&cancel);
	}
	return true;
}
