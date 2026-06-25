/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef VAPORETTO_WINDOW_H
#define VAPORETTO_WINDOW_H


#include <Window.h>


// Easter egg triggered by tapping the logo tile in HeaderView seven times
// in a row. Draws an ACTV vaporetto on the lagoon -- a nod to the Venetian
// spirit of the project ("sotoportego" is a covered passage in a Venetian
// alley). Plain non-modal window so the rest of the UI stays usable.
class VaporettoWindow : public BWindow {
public:
								VaporettoWindow();
};


#endif	// VAPORETTO_WINDOW_H
