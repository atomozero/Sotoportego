/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "SotoportegoApp.h"

#include <AboutWindow.h>
#include <Bitmap.h>

#include "HeaderView.h"
#include "MainWindow.h"
#include "VPNProtocol.h"


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
	BAboutWindow* about = new BAboutWindow("Sotoportego", kGUISignature);

	BBitmap* icon = HeaderView::MakeLogoBitmap(64);
	if (icon != NULL)
		about->SetIcon(icon);

	about->SetVersion("0.1 (development)");
	about->AddCopyright(2026, "atomozero");
	about->AddDescription(
		"Sotoportego is a native VPN client for Haiku. The daemon owns the "
		"VPN lifecycle and is the single source of truth; the GUI, CLI and "
		"the upcoming Deskbar replicant are thin front-ends that subscribe "
		"to its broadcasts over BMessage.\n\n"
		"Milestone 1 skeleton \xe2\x80\x94 the connection is still a stub.");
	const char* authors[] = {
		"atomozero",
		NULL
	};
	about->AddAuthors(authors);
	about->Show();
}
