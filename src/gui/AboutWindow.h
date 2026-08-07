/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef SOTO_ABOUT_WINDOW_H
#define SOTO_ABOUT_WINDOW_H


#include <Window.h>


// The "About Sotoportego" window: a gradient slate banner with the app icon
// on a rounded blue tile, title and version, a short description, author, a
// clickable project link and license line. Same style (and same components)
// as the About window in the author's other native Haiku apps (Atomo123,
// Brube2000), reused here for visual consistency across the family.
class AboutWindow : public BWindow {
public:
							AboutWindow();

	virtual	void			MessageReceived(BMessage* message);
};


#endif	// SOTO_ABOUT_WINDOW_H
