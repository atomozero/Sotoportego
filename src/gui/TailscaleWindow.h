/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TAILSCALE_WINDOW_H
#define TAILSCALE_WINDOW_H


#include <Messenger.h>
#include <Window.h>

class BButton;
class BTextControl;


// BMessage fields on the OK reply: the tailnet profile name and the control
// server URL (defaults to Tailscale's coordination server; a Headscale URL goes
// here for self-hosted).
extern const char* const kFieldTsName;
extern const char* const kFieldTsUrl;
// Optional pre-auth key (empty string when the user leaves it blank).
extern const char* const kFieldTsAuthKey;


// A small dialog that creates a Tailscale connection profile. Unlike the
// OpenVPN/WireGuard flow there's no file to import -- a tailnet is just a name
// plus which control server to talk to -- so this collects those two fields and
// posts them back; the parent turns them into a VPN_BACKEND_TAILSCALE profile
// saved through the daemon, after which it behaves like any other profile.
class TailscaleWindow : public BWindow {
public:
								TailscaleWindow(BWindow* parent,
									const BMessenger& target, uint32 onOK);

	virtual	void				MessageReceived(BMessage* message);

private:
			BMessenger			fTarget;
			uint32				fOnOK;
			BTextControl*		fNameField;
			BTextControl*		fUrlField;
			BTextControl*		fAuthKeyField;
			BButton*			fAddButton;
			BButton*			fCancelButton;
};


#endif	// TAILSCALE_WINDOW_H
