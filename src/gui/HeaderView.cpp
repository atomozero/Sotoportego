/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "HeaderView.h"

#include <Bitmap.h>
#include <Font.h>
#include <IconUtils.h>

#include "sotoportego_icon_data.h"


// Visual constants. Match the slate/title/subtitle tones used by Mose so the
// two apps feel like part of the same family on the desktop.
static const rgb_color kHeaderBg		= { 40, 50, 65, 255 };
static const rgb_color kHeaderTitle		= { 245, 245, 245, 255 };
static const rgb_color kHeaderSubtitle	= { 180, 195, 210, 255 };
static const rgb_color kDotStroke		= { 255, 255, 255, 255 };

// Logo tile (fallback fill if HVIF rendering ever fails).
static const rgb_color kLogoFill		= { 90, 155, 213, 255 };

// State accents, used for the small status dot overlaid on the logo tile.
// Same family as Mose's allow/drop indicators, extended with an "in-progress"
// amber for the connecting/authenticating/reconnecting transitions.
static const rgb_color kAccentIdle		= { 160, 160, 160, 255 };
static const rgb_color kAccentProgress	= { 224, 160, 48, 255 };
static const rgb_color kAccentConnected	= { 90, 200, 120, 255 };
static const rgb_color kAccentError		= { 220, 80, 80, 255 };

static const float kHeaderHeight		= 64.0f;
static const float kIconX				= 14.0f;
static const float kIconY				= 12.0f;
static const float kIconSize			= 40.0f;
static const float kTextX				= 68.0f;
static const float kTitleBaselineY		= 27.0f;
static const float kSubtitleBaselineY	= 47.0f;


static rgb_color
_AccentFor(VPNState state)
{
	switch (state) {
		case VPN_STATE_CONNECTING:
		case VPN_STATE_AUTHENTICATING:
		case VPN_STATE_RECONNECTING:
			return kAccentProgress;
		case VPN_STATE_CONNECTED:
			return kAccentConnected;
		case VPN_STATE_ERROR:
			return kAccentError;
		case VPN_STATE_DISCONNECTED:
		default:
			return kAccentIdle;
	}
}


HeaderView::HeaderView(const char* name)
	:
	BView(name, B_WILL_DRAW | B_SUPPORTS_LAYOUT | B_FULL_UPDATE_ON_RESIZE),
	fState(VPN_STATE_DISCONNECTED),
	fSubtitle("Disconnected"),
	fEasterTarget(),
	fEasterWhat(0),
	fLastTileClick(0),
	fTileClickStreak(0)
{
	SetViewColor(kHeaderBg);
	SetLowColor(kHeaderBg);
}


void
HeaderView::SetEasterEggTarget(const BMessenger& target, uint32 what)
{
	fEasterTarget = target;
	fEasterWhat = what;
}


void
HeaderView::SetState(VPNState state)
{
	if (state == fState)
		return;
	fState = state;
	Invalidate();
}


void
HeaderView::SetSubtitle(const char* text)
{
	BString next(text != NULL ? text : "");
	if (next == fSubtitle)
		return;
	fSubtitle = next;
	Invalidate();
}


void
HeaderView::Draw(BRect /*updateRect*/)
{
	BRect bounds = Bounds();

	// Solid slate background.
	SetHighColor(kHeaderBg);
	FillRect(bounds);

	BRect iconRect(kIconX, kIconY, kIconX + kIconSize - 1,
		kIconY + kIconSize - 1);
	_DrawLogoTile(iconRect);
	_DrawStatusDot(iconRect);

	// Title and subtitle. SetLowColor matches kHeaderBg so antialiased glyphs
	// blend cleanly against the slate.
	SetDrawingMode(B_OP_OVER);

	BFont titleFont(be_bold_font);
	titleFont.SetSize(18.0f);
	SetFont(&titleFont);
	SetHighColor(kHeaderTitle);
	DrawString("Sotoportego", BPoint(kTextX, kTitleBaselineY));

	BFont subFont(be_plain_font);
	subFont.SetSize(11.0f);
	SetFont(&subFont);
	SetHighColor(kHeaderSubtitle);
	DrawString(fSubtitle.String(), BPoint(kTextX, kSubtitleBaselineY));
}


// Render the brand HVIF into a freshly allocated RGBA bitmap of `size`
// pixels (square). Returns NULL if the icon data fails to rasterise. Caller
// owns the bitmap.
static BBitmap*
_RenderHvif(float size)
{
	BBitmap* bitmap = new BBitmap(BRect(0, 0, size - 1, size - 1), 0,
		B_RGBA32);
	if (bitmap == NULL || bitmap->InitCheck() != B_OK) {
		delete bitmap;
		return NULL;
	}
	status_t result = BIconUtils::GetVectorIcon(
		(const uint8*)kIconHvif, kIconHvifSize, bitmap);
	if (result != B_OK) {
		delete bitmap;
		return NULL;
	}
	return bitmap;
}


void
HeaderView::_DrawLogoTile(BRect rect)
{
	BBitmap* icon = _RenderHvif(rect.Width());
	if (icon != NULL) {
		// Alpha-blend the icon so transparent pixels keep the slate header
		// visible underneath.
		SetDrawingMode(B_OP_ALPHA);
		SetBlendingMode(B_PIXEL_ALPHA, B_ALPHA_OVERLAY);
		DrawBitmap(icon, rect.LeftTop());
		SetDrawingMode(B_OP_COPY);
		delete icon;
		return;
	}

	// Fallback: a flat brand-color rounded tile if the icon could not be
	// rasterised for any reason. Keeps the header looking intentional rather
	// than empty.
	float radius = rect.Width() * 0.18f;
	SetHighColor(kLogoFill);
	FillRoundRect(rect, radius, radius);
}


void
HeaderView::MouseDown(BPoint where)
{
	// Easter egg: seven taps on the logo tile within three seconds opens
	// the Vaporetto window. Trip the counter only for clicks that actually
	// land on the tile so accidental drag-by clicks on the text don't
	// count.
	BRect tile(kIconX, kIconY, kIconX + kIconSize - 1,
		kIconY + kIconSize - 1);
	if (!tile.Contains(where))
		return;
	if (!fEasterTarget.IsValid() || fEasterWhat == 0)
		return;

	const bigtime_t kStreakWindow = 3 * 1000000;	// 3 seconds
	const int32 kStreakGoal = 7;

	bigtime_t now = system_time();
	if (now - fLastTileClick > kStreakWindow)
		fTileClickStreak = 0;
	fLastTileClick = now;
	fTileClickStreak++;

	if (fTileClickStreak >= kStreakGoal) {
		fTileClickStreak = 0;
		BMessage trigger(fEasterWhat);
		fEasterTarget.SendMessage(&trigger);
	}
}


void
HeaderView::_DrawStatusDot(BRect iconRect)
{
	// Small filled circle overlaid on the bottom-right corner of the logo
	// tile, white-bordered for a crisp edge against any tile color.
	const float dotSize = 14.0f;
	BRect dot(0, 0, dotSize - 1, dotSize - 1);
	dot.OffsetTo(iconRect.right - dotSize + 4, iconRect.bottom - dotSize + 4);

	SetDrawingMode(B_OP_ALPHA);
	SetHighColor(_AccentFor(fState));
	FillEllipse(dot);
	SetHighColor(kDotStroke);
	StrokeEllipse(dot);
	SetDrawingMode(B_OP_COPY);
}


BSize
HeaderView::MinSize()
{
	return BSize(360.0f, kHeaderHeight);
}


BSize
HeaderView::MaxSize()
{
	return BSize(B_SIZE_UNLIMITED, kHeaderHeight);
}


BSize
HeaderView::PreferredSize()
{
	return BSize(540.0f, kHeaderHeight);
}


BBitmap*
HeaderView::MakeLogoBitmap(float size)
{
	// Same path as the header's icon rendering, so the About dialog and the
	// header always show the same image.
	return _RenderHvif(size);
}

