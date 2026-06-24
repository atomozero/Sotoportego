/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef HEADER_VIEW_H
#define HEADER_VIEW_H


#include <InterfaceDefs.h>
#include <String.h>
#include <View.h>

#include "VPNState.h"

class BBitmap;


// The dark banner at the top of the main window. Mirrors the look used by
// Mose: a slate background, a colored "logo tile" on the left, a status dot
// overlaid on the tile, and the application name + a single info line of
// metadata on the right. The whole strip is custom-drawn (no child views),
// which keeps the layout simple and lets the colors carry the state at a
// glance.
class HeaderView : public BView {
public:
								HeaderView(const char* name);

			// Update the state (drives the status-dot color) and the
			// metadata line (e.g. "Disconnected" or "Connected - vpn:1194").
			void				SetState(VPNState state);
			void				SetSubtitle(const char* text);

	virtual	void				Draw(BRect updateRect);
	virtual	BSize				MinSize();
	virtual	BSize				MaxSize();
	virtual	BSize				PreferredSize();

	// Render the same brand tile (rounded square + "S" glyph) the header
	// shows, into a freshly allocated RGBA bitmap of the requested size.
	// Used by the About dialog so it carries the same identity. Caller owns
	// the returned bitmap (may return NULL on failure).
	static	BBitmap*			MakeLogoBitmap(float size);

private:
			void				_DrawLogoTile(BRect rect);
			void				_DrawStatusDot(BRect iconRect);

			VPNState			fState;
			BString				fSubtitle;
};


#endif	// HEADER_VIEW_H
