/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef CLICKABLE_STRING_VIEW_H
#define CLICKABLE_STRING_VIEW_H


#include <StringView.h>


// A BStringView that posts a message when clicked and shows the "follow link"
// cursor on hover -- used for the project link in the About window. Mirrors the
// component the author uses in his other native Haiku apps (Atomo123, Brube2000)
// so the About windows share the same look.
class ClickableStringView : public BStringView {
public:
							ClickableStringView(const char* name,
								const char* text);
	virtual					~ClickableStringView();

	virtual	void			AttachedToWindow();
	virtual	void			MouseDown(BPoint where);
	virtual	void			MouseMoved(BPoint where, uint32 code,
								const BMessage* message);

			void			SetClickMessage(BMessage* message);

private:
			BMessage*		fClickMessage;
};


#endif	// CLICKABLE_STRING_VIEW_H
