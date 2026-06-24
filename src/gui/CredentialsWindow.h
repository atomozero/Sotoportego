/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef CREDENTIALS_WINDOW_H
#define CREDENTIALS_WINDOW_H


#include <Messenger.h>
#include <String.h>
#include <Window.h>

class BButton;
class BTextControl;


// Modal credentials prompt shown before a Connect when the active profile
// might need username/password authentication. On OK, posts a configurable
// message back to the parent containing two strings; the parent message
// builds the Connect request from them. On Cancel, posts the cancel message
// (with no fields) so the parent knows to drop the pending Connect.
class CredentialsWindow : public BWindow {
public:
								CredentialsWindow(BWindow* parent,
									const BMessenger& target,
									uint32 onOK, uint32 onCancel,
									const char* profileName,
									const BString& prefilledUser);

	virtual	void				MessageReceived(BMessage* message);
	virtual	bool				QuitRequested();

private:
			BMessenger			fTarget;
			uint32				fOnOK;
			uint32				fOnCancel;
			BTextControl*		fUserField;
			BTextControl*		fPasswordField;
			BButton*			fOKButton;
			BButton*			fCancelButton;
			bool				fSent;
};


#endif	// CREDENTIALS_WINDOW_H
