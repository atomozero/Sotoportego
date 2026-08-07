/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "ClickableStringView.h"

#include <Cursor.h>
#include <Message.h>
#include <Window.h>


ClickableStringView::ClickableStringView(const char* name, const char* text)
	:
	BStringView(name, text),
	fClickMessage(NULL)
{
}


ClickableStringView::~ClickableStringView()
{
	delete fClickMessage;
}


void
ClickableStringView::AttachedToWindow()
{
	BStringView::AttachedToWindow();
	// Hyperlink colour, but only when there is actually a message to post.
	if (fClickMessage != NULL)
		SetHighColor(40, 80, 200);
}


void
ClickableStringView::SetClickMessage(BMessage* message)
{
	delete fClickMessage;
	fClickMessage = message;
}


void
ClickableStringView::MouseDown(BPoint /*where*/)
{
	if (fClickMessage == NULL || Window() == NULL)
		return;
	Window()->PostMessage(fClickMessage);
}


void
ClickableStringView::MouseMoved(BPoint /*where*/, uint32 /*code*/,
	const BMessage* /*message*/)
{
	if (fClickMessage == NULL)
		return;
	BCursor link(B_CURSOR_ID_FOLLOW_LINK);
	SetViewCursor(&link);
}
