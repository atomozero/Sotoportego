/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "HeaderView.h"

#include <Bitmap.h>
#include <Font.h>


// Visual constants. Match the slate/title/subtitle tones used by Mose so the
// two apps feel like part of the same family on the desktop.
static const rgb_color kHeaderBg		= { 40, 50, 65, 255 };
static const rgb_color kHeaderTitle		= { 245, 245, 245, 255 };
static const rgb_color kHeaderSubtitle	= { 180, 195, 210, 255 };
static const rgb_color kDotStroke		= { 255, 255, 255, 255 };

// Logo tile (fixed brand color, independent from state).
static const rgb_color kLogoFill		= { 90, 155, 213, 255 };
static const rgb_color kLogoGlyph		= { 255, 255, 255, 255 };

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
	fSubtitle("Disconnected")
{
	SetViewColor(kHeaderBg);
	SetLowColor(kHeaderBg);
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


void
HeaderView::_DrawLogoTile(BRect rect)
{
	// Rounded brand-color tile.
	float radius = rect.Width() * 0.18f;
	SetHighColor(kLogoFill);
	FillRoundRect(rect, radius, radius);

	// White "S" centered on the tile. The "S" stands in for a real HVIF icon
	// until we ship one; using a bold glyph keeps the file size down and the
	// look consistent with the rest of the (font-driven) UI.
	BFont glyphFont(be_bold_font);
	glyphFont.SetSize(rect.Height() * 0.62f);
	SetFont(&glyphFont);

	font_height fh;
	glyphFont.GetHeight(&fh);
	const char* glyph = "S";
	float textWidth = glyphFont.StringWidth(glyph);
	float baselineY = rect.top
		+ (rect.Height() + fh.ascent - fh.descent) / 2.0f;
	float baselineX = rect.left + (rect.Width() - textWidth) / 2.0f;

	SetHighColor(kLogoGlyph);
	DrawString(glyph, BPoint(baselineX, baselineY));
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


// Helper view that knows how to paint the brand tile into its bounds.
// Offscreen rendering on Haiku needs a BView attached to a BBitmap; the bitmap
// is locked, the view's Draw() is invoked manually, then the bitmap is
// unlocked and detached.
namespace {

class LogoRenderView : public BView {
public:
	LogoRenderView(BRect frame)
		:
		BView(frame, "logoRender", B_FOLLOW_NONE, B_WILL_DRAW)
	{
		SetViewColor(B_TRANSPARENT_COLOR);
	}

	void Paint()
	{
		BRect r = Bounds();

		// Same rounded brand-color tile as the header's logo.
		float radius = r.Width() * 0.18f;
		SetHighColor(kLogoFill);
		FillRoundRect(r, radius, radius);

		BFont glyphFont(be_bold_font);
		glyphFont.SetSize(r.Height() * 0.62f);
		SetFont(&glyphFont);

		font_height fh;
		glyphFont.GetHeight(&fh);
		const char* glyph = "S";
		float textWidth = glyphFont.StringWidth(glyph);
		float baselineY = r.top
			+ (r.Height() + fh.ascent - fh.descent) / 2.0f;
		float baselineX = r.left + (r.Width() - textWidth) / 2.0f;

		SetHighColor(kLogoGlyph);
		DrawString(glyph, BPoint(baselineX, baselineY));
		Sync();
	}
};

}	// namespace


BBitmap*
HeaderView::MakeLogoBitmap(float size)
{
	BRect frame(0, 0, size - 1, size - 1);
	BBitmap* bitmap = new BBitmap(frame, B_RGBA32, true);
	if (bitmap == NULL || bitmap->InitCheck() != B_OK) {
		delete bitmap;
		return NULL;
	}

	LogoRenderView* view = new LogoRenderView(frame);
	bitmap->AddChild(view);
	if (bitmap->Lock()) {
		view->Paint();
		bitmap->Unlock();
	}
	bitmap->RemoveChild(view);
	delete view;

	return bitmap;
}

