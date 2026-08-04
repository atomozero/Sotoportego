/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef HEADER_VIEW_H
#define HEADER_VIEW_H


#include <InterfaceDefs.h>
#include <Messenger.h>
#include <String.h>
#include <View.h>

#include "VPNState.h"

class BBitmap;
class BButton;


// The dark banner at the top of the main window. Mirrors the look used by
// Mose: a slate background, a colored "logo tile" on the left, a status dot
// overlaid on the tile, and the application name + a single info line of
// metadata on the right. The whole strip is custom-drawn (no child views),
// which keeps the layout simple and lets the colors carry the state at a
// glance.
class HeaderView : public BView {
public:
								HeaderView(const char* name);
	virtual						~HeaderView();

			// Update the state (drives the status-dot color) and the
			// metadata line (e.g. "Disconnected" or "Connected - vpn:1194").
			void				SetState(VPNState state);
			void				SetSubtitle(const char* text);

			// Host the primary Connect/Disconnect button on the right of the
			// banner. The button is reparented to (and thereafter owned by)
			// the header's view tree; the header keeps it right-aligned and
			// vertically centred as the window resizes.
			void				SetActionButton(BButton* button);

	virtual	void				Draw(BRect updateRect);
	virtual	void				FrameResized(float width, float height);
	virtual	void				MouseDown(BPoint where);
	virtual	BSize				MinSize();
	virtual	BSize				MaxSize();
	virtual	BSize				PreferredSize();

	// Render the same brand tile (rounded square + "S" glyph) the header
	// shows, into a freshly allocated RGBA bitmap of the requested size.
	// Used by the About dialog so it carries the same identity. Caller owns
	// the returned bitmap (may return NULL on failure).
	static	BBitmap*			MakeLogoBitmap(float size);

	// A messenger that should receive a `wMsg` BMessage when the logo tile
	// is tapped enough times in a row -- the easter-egg trigger. No-op if
	// the messenger is invalid.
			void				SetEasterEggTarget(const BMessenger& target,
									uint32 what);

private:
			void				_DrawLogoTile(BRect rect);
			void				_DrawStatusDot(BRect iconRect);
			void				_LayoutActionButton();

			VPNState			fState;
			BString				fSubtitle;
			BButton*			fActionButton;
			BMessenger			fEasterTarget;
			uint32				fEasterWhat;
			bigtime_t			fLastTileClick;
			int32				fTileClickStreak;

	// Cached rasterised HVIF for the logo tile. Re-allocated only when
	// the requested size changes, so a redraw at the same size is a flat
	// DrawBitmap rather than a vector rasterise + RGBA allocation every
	// time the window is invalidated.
			BBitmap*			fCachedIcon;
			float				fCachedIconSize;
};


#endif	// HEADER_VIEW_H
