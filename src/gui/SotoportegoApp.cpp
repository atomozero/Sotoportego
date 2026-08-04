/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "SotoportegoApp.h"

#include "AboutWindow.h"
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
	(new AboutWindow())->Show();
}
