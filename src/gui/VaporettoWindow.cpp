/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "VaporettoWindow.h"

#include <math.h>

#include <Font.h>
#include <Message.h>
#include <MessageRunner.h>
#include <Messenger.h>
#include <Point.h>
#include <Polygon.h>
#include <Rect.h>
#include <Region.h>
#include <View.h>


// Lagoon palette tuned to read warm-Venetian rather than blue-postcard.
static const rgb_color kSkyTop		= { 252, 222, 178, 255 };	// dawn peach
static const rgb_color kSkyBottom	= { 244, 198, 140, 255 };	// sun haze
static const rgb_color kWaterTop	= { 78, 132, 142, 255 };	// lagoon teal
static const rgb_color kWaterBottom	= { 38, 72, 92, 255 };		// deep canal
static const rgb_color kWaveCrest	= { 235, 240, 240, 255 };
static const rgb_color kRipple		= { 200, 220, 222, 200 };

// Vaporetto livery -- white hull, broad ACTV yellow band, red along the
// waterline, dark grey accents.
static const rgb_color kHull		= { 252, 252, 250, 255 };
static const rgb_color kHullShadow	= { 200, 200, 198, 255 };
static const rgb_color kBandYellow	= { 252, 198, 24, 255 };
static const rgb_color kBandShadow	= { 196, 144, 8, 255 };
static const rgb_color kWaterline	= { 188, 54, 50, 255 };
static const rgb_color kFlagRed		= { 196, 60, 56, 255 };
static const rgb_color kWindowFrame	= { 40, 50, 60, 255 };
static const rgb_color kWindowGlass	= { 162, 188, 200, 255 };
static const rgb_color kWindowGlare	= { 232, 240, 244, 255 };
static const rgb_color kBlack		= { 32, 36, 42, 255 };
static const rgb_color kCaption		= { 80, 92, 104, 255 };


namespace {

static const uint32 kMsgTick = 'vTik';
// 60ms ~= 16fps. Plenty for a slow lagoon swell and cheap to redraw.
static const bigtime_t kTickInterval = 60000;


class VaporettoView : public BView {
public:
	VaporettoView(BRect frame)
		:
		BView(frame, "vaporetto", B_FOLLOW_ALL_SIDES,
			B_WILL_DRAW | B_FRAME_EVENTS),
		fPhase(0.0f),
		fTimer(NULL)
	{
		SetViewColor(B_TRANSPARENT_COLOR);
	}

	virtual ~VaporettoView()
	{
		delete fTimer;
	}

	virtual void AttachedToWindow()
	{
		if (fTimer == NULL) {
			BMessage tick(kMsgTick);
			fTimer = new BMessageRunner(BMessenger(this), &tick,
				kTickInterval);
		}
	}

	virtual void MessageReceived(BMessage* msg)
	{
		if (msg->what == kMsgTick) {
			// Advance the wave phase. Reset once it wanders far enough
			// that float precision starts to bite.
			fPhase += 1.0f;
			if (fPhase > 1.0e6f)
				fPhase = 0.0f;
			Invalidate();
			return;
		}
		BView::MessageReceived(msg);
	}

	virtual void Draw(BRect /*updateRect*/)
	{
		BRect b = Bounds();
		_DrawSky(b);
		_DrawWater(b);
		_DrawReflection(b);
		_DrawVaporetto(b);
		_DrawCaption(b);
	}

private:
			float				fPhase;
			BMessageRunner*		fTimer;

	void _FillVerticalGradient(BRect rect, rgb_color top, rgb_color bottom)
	{
		// Per-row strokes give us a precise gradient without pulling in
		// BGradientLinear; the strip is only ~150 lines tall.
		for (float y = rect.top; y <= rect.bottom; y += 1.0f) {
			float t = (y - rect.top) / (rect.Height() + 1.0f);
			rgb_color c;
			c.red   = (uint8)(top.red   + (bottom.red   - top.red)   * t);
			c.green = (uint8)(top.green + (bottom.green - top.green) * t);
			c.blue  = (uint8)(top.blue  + (bottom.blue  - top.blue)  * t);
			c.alpha = 255;
			SetHighColor(c);
			StrokeLine(BPoint(rect.left, y), BPoint(rect.right, y));
		}
	}

	void _DrawSky(BRect b)
	{
		BRect sky = b;
		sky.bottom = b.top + b.Height() * 0.62f;
		_FillVerticalGradient(sky, kSkyTop, kSkyBottom);
	}

	void _DrawWater(BRect b)
	{
		BRect water = b;
		water.top = b.top + b.Height() * 0.62f;
		_FillVerticalGradient(water, kWaterTop, kWaterBottom);

		// Each row drifts left to right at a slightly different speed; the
		// fPhase term is what makes the crests crawl across the canvas as
		// the timer ticks.
		SetHighColor(kWaveCrest);
		for (int row = 0; row < 5; row++) {
			float y = water.top + 16.0f + row * 18.0f;
			float rowPhase = row * 23.0f;
			float drift = fPhase * (1.4f + row * 0.25f);
			for (float x = water.left + 4.0f - 32.0f; x < water.right + 32.0f;
					x += 28.0f) {
				float xs = x + fmodf(drift, 28.0f);
				float dy = 2.0f * sinf((xs + rowPhase) * 0.06f
					+ fPhase * 0.05f);
				StrokeLine(BPoint(xs, y + dy),
					BPoint(xs + 12.0f, y + dy));
			}
		}
	}

	void _DrawReflection(BRect b)
	{
		// A handful of broken horizontal stripes right under the boat
		// suggest a wobbly mirror image of the hull on the water. The
		// breaks slide sideways as the phase advances so the reflection
		// shimmers.
		float cx = b.left + b.Width() / 2.0f;
		float wl = b.top + b.Height() * 0.70f;
		float halfLen = std::min(b.Width() * 0.40f, 220.0f);
		SetHighColor(kRipple);
		SetDrawingMode(B_OP_ALPHA);
		for (int i = 0; i < 6; i++) {
			float y = wl + 4 + i * 4;
			float inset = i * 8;
			float drift = fmodf(fPhase * (0.8f + i * 0.15f), 28.0f);
			StrokeLine(BPoint(cx - halfLen + inset + drift, y),
				BPoint(cx - halfLen * 0.3f + inset + drift, y));
			StrokeLine(BPoint(cx - halfLen * 0.1f + inset - drift, y),
				BPoint(cx + halfLen * 0.6f - inset - drift, y));
		}
		SetDrawingMode(B_OP_COPY);
	}

	void _DrawVaporetto(BRect b)
	{
		// Geometry. The boat is centred horizontally and sits at ~66% of
		// the view's height. All measurements are derived from boatLen so
		// the whole thing scales with the window's width.
		float cx = b.left + b.Width() / 2.0f;
		// Subtle vertical bob synced to the wave phase so the boat looks
		// like it's riding the swell instead of nailed to the canvas.
		float bob = sinf(fPhase * 0.05f) * 1.4f;
		float wl = b.top + b.Height() * 0.70f + bob;

		const float boatLen = b.Width() * 0.78f;
		const float halfLen = boatLen / 2.0f;
		const float prowX = cx + halfLen;	// boat faces right
		const float sternX = cx - halfLen;

		const float hullH = 24.0f;
		const float cabinH = 30.0f;
		const float roofH = 5.0f;
		const float deckY = wl - hullH;
		const float cabinTop = deckY - cabinH;
		const float roofTop = cabinTop - roofH;

		// The cabin doesn't run to the ends of the boat: an open foredeck
		// (long, where the helmsman stands) and a rear gangway are part of
		// the vaporetto's silhouette.
		const float cabinFrontX = prowX - boatLen * 0.16f;
		const float cabinBackX = sternX + boatLen * 0.12f;

		// ─── Hull ─────────────────────────────────────────────────────
		// Long flat-bottomed shape with raked ends. Many vertices give the
		// outline a chiselled, intentional feel rather than the boxy
		// silhouette of a shipping container.
		BPoint hull[] = {
			BPoint(sternX + 16,     wl + 4),
			BPoint(sternX + 6,      wl + 2),
			BPoint(sternX,          wl - 4),
			BPoint(sternX + 4,      deckY + 4),
			BPoint(sternX + 14,     deckY),
			BPoint(prowX - 36,      deckY),
			BPoint(prowX - 18,      deckY - 6),
			BPoint(prowX - 4,       deckY - 8),
			BPoint(prowX,           deckY - 4),
			BPoint(prowX,           wl - 2),
			BPoint(prowX - 6,       wl + 1),
			BPoint(prowX - 14,      wl + 4),
		};
		const int hullN = sizeof(hull) / sizeof(hull[0]);
		BPolygon hullPoly(hull, hullN);

		// Drop shadow.
		BPoint hullShadowPts[hullN];
		for (int i = 0; i < hullN; i++) {
			hullShadowPts[i] = hull[i];
			hullShadowPts[i].y += 3;
			hullShadowPts[i].x += 1;
		}
		BPolygon hullShadow(hullShadowPts, hullN);
		SetHighColor(kHullShadow);
		FillPolygon(&hullShadow);

		// White body.
		SetHighColor(kHull);
		FillPolygon(&hullPoly);

		// ─── Yellow ACTV band ─────────────────────────────────────────
		// Clip the band to the hull silhouette so it follows the prow
		// and stern rakes instead of poking out beyond them.
		BRegion hullRegion;
		hullRegion.Include(hullPoly.Frame());
		// We can't construct a region from a polygon directly on Haiku;
		// approximate by clipping a rectangle to the rough shape via a
		// rectangle whose top/bottom sit inside the hull's middle stripe.
		BRect bandRect(sternX + 8, deckY + 3, prowX - 10, deckY + 12);
		SetHighColor(kBandShadow);
		FillRect(BRect(bandRect.left, bandRect.bottom - 1,
			bandRect.right, bandRect.bottom));
		SetHighColor(kBandYellow);
		FillRect(BRect(bandRect.left, bandRect.top,
			bandRect.right, bandRect.bottom - 1));

		// "ACTV" centred on the yellow band, as on the real boats.
		// Bold black on yellow is the canonical livery.
		BFont actv(be_bold_font);
		actv.SetSize(8.0f);
		SetFont(&actv);
		SetHighColor(kBlack);
		SetDrawingMode(B_OP_OVER);
		font_height actvFh;
		actv.GetHeight(&actvFh);
		float actvW = actv.StringWidth("ACTV");
		float actvY = bandRect.top
			+ (bandRect.Height() + actvFh.ascent - actvFh.descent) / 2.0f
			- 1.0f;
		DrawString("ACTV",
			BPoint(bandRect.left + (bandRect.Width() - actvW) / 2.0f,
				actvY));
		SetDrawingMode(B_OP_COPY);

		// ─── Red waterline ────────────────────────────────────────────
		SetHighColor(kWaterline);
		FillRect(BRect(sternX + 6, wl - 1, prowX - 6, wl + 3));

		// Final hull outline goes on top so the band and waterline tuck
		// in cleanly.
		SetHighColor(kBlack);
		StrokePolygon(&hullPoly);

		// ─── Cabin ────────────────────────────────────────────────────
		// Body with a slightly raked windshield at the front (right side).
		const float windshieldRake = 12.0f;
		BPoint cabin[] = {
			BPoint(cabinBackX,                  deckY),
			BPoint(cabinBackX,                  cabinTop + 2),
			BPoint(cabinBackX + 4,              cabinTop),
			BPoint(cabinFrontX - 14,            cabinTop),
			BPoint(cabinFrontX,                 cabinTop + windshieldRake),
			BPoint(cabinFrontX,                 deckY),
		};
		const int cabinN = sizeof(cabin) / sizeof(cabin[0]);
		BPolygon cabinPoly(cabin, cabinN);
		SetHighColor(kHull);
		FillPolygon(&cabinPoly);
		SetHighColor(kBlack);
		StrokePolygon(&cabinPoly);

		// ─── Roof ─────────────────────────────────────────────────────
		// Slight overhang front and back. Drawn as a polygon so the front
		// edge can ride the windshield's rake.
		BPoint roof[] = {
			BPoint(cabinBackX - 4,          cabinTop),
			BPoint(cabinBackX - 4,          roofTop),
			BPoint(cabinFrontX - 6,         roofTop),
			BPoint(cabinFrontX + 2,         cabinTop + windshieldRake * 0.4f),
			BPoint(cabinFrontX - 10,        cabinTop),
		};
		const int roofN = sizeof(roof) / sizeof(roof[0]);
		BPolygon roofPoly(roof, roofN);
		SetHighColor(kHull);
		FillPolygon(&roofPoly);
		SetHighColor(kBlack);
		StrokePolygon(&roofPoly);

		// Yellow band along the top edge of the cabin, just under the
		// roof, mirroring the hull band.
		BRect topBand(cabinBackX + 2, cabinTop + 1,
			cabinFrontX - 14, cabinTop + 5);
		SetHighColor(kBandYellow);
		FillRect(topBand);

		// ─── Windows ──────────────────────────────────────────────────
		// Row of tall rectangles fills most of the cabin. The windshield
		// at the prow end is a separate, larger pane.
		const float winTop = cabinTop + 7;
		const float winBot = deckY - 5;
		const float winsLeft = cabinBackX + 6;
		const float winsRight = cabinFrontX - 22;
		const int   nWindows = 10;
		const float gap = 3.0f;
		const float winW = (winsRight - winsLeft
			- (nWindows - 1) * gap) / nWindows;
		for (int i = 0; i < nWindows; i++) {
			float x = winsLeft + i * (winW + gap);
			BRect win(x, winTop, x + winW, winBot);
			SetHighColor(kWindowGlass);
			FillRect(win);
			// Diagonal glare highlight on the top-left.
			SetHighColor(kWindowGlare);
			BPoint glare[] = {
				BPoint(win.left + 1, win.top + 1),
				BPoint(win.left + winW * 0.45f, win.top + 1),
				BPoint(win.left + 1, win.top + (winBot - winTop) * 0.45f),
			};
			BPolygon glarePoly(glare, 3);
			FillPolygon(&glarePoly);
			SetHighColor(kWindowFrame);
			StrokeRect(win);
		}

		// Front windshield: trapezoid that follows the windshield rake.
		BPoint ws[] = {
			BPoint(cabinFrontX - 18,      cabinTop + 6),
			BPoint(cabinFrontX - 4,       cabinTop + windshieldRake),
			BPoint(cabinFrontX - 4,       deckY - 5),
			BPoint(cabinFrontX - 18,      deckY - 5),
		};
		BPolygon wsPoly(ws, sizeof(ws) / sizeof(ws[0]));
		SetHighColor(kWindowGlass);
		FillPolygon(&wsPoly);
		SetHighColor(kWindowGlare);
		BPoint wsGlare[] = {
			BPoint(cabinFrontX - 17, cabinTop + 7),
			BPoint(cabinFrontX - 10, cabinTop + 9),
			BPoint(cabinFrontX - 17, cabinTop + 18),
		};
		BPolygon wsGlarePoly(wsGlare, 3);
		FillPolygon(&wsGlarePoly);
		SetHighColor(kWindowFrame);
		StrokePolygon(&wsPoly);

		// ─── Funnel ───────────────────────────────────────────────────
		// Short stack near the back of the cabin with the classic yellow
		// ring around the top third.
		BRect funnel(cabinBackX + 16, roofTop - 12,
			cabinBackX + 26, roofTop);
		SetHighColor(kHull);
		FillRect(funnel);
		SetHighColor(kBandYellow);
		FillRect(BRect(funnel.left, funnel.top + 1,
			funnel.right, funnel.top + 5));
		SetHighColor(kBlack);
		StrokeRect(funnel);
		// Tiny black cap.
		FillRect(BRect(funnel.left - 1, funnel.top - 1,
			funnel.right + 1, funnel.top + 1));

		// ─── Roof rail ────────────────────────────────────────────────
		// Single horizontal rail with thin vertical posts.
		SetHighColor(kBlack);
		float railY = roofTop - 3;
		StrokeLine(BPoint(cabinBackX, railY),
			BPoint(cabinFrontX - 18, railY));
		for (float x = cabinBackX; x < cabinFrontX - 18; x += 22) {
			StrokeLine(BPoint(x, railY), BPoint(x, roofTop));
		}

		// ─── Open-deck railings (fore and aft) ────────────────────────
		float openRailY = deckY - 11;
		SetHighColor(kBlack);
		// Foredeck (between cabin and prow).
		StrokeLine(BPoint(cabinFrontX + 2, openRailY),
			BPoint(prowX - 18, openRailY));
		for (float x = cabinFrontX + 4; x < prowX - 18; x += 8) {
			StrokeLine(BPoint(x, openRailY), BPoint(x, deckY));
		}
		// Stern gangway.
		StrokeLine(BPoint(sternX + 16, openRailY),
			BPoint(cabinBackX - 2, openRailY));
		for (float x = sternX + 18; x < cabinBackX - 2; x += 8) {
			StrokeLine(BPoint(x, openRailY), BPoint(x, deckY));
		}

		// ─── Route badge "1" on the cabin side ────────────────────────
		// The iconic ACTV line number disc -- a quick, telling detail.
		BRect badge(cabinBackX + 32, cabinTop + 11,
			cabinBackX + 48, cabinTop + 27);
		SetHighColor(kHull);
		FillEllipse(badge);
		SetHighColor(kBlack);
		StrokeEllipse(badge);
		BFont badgeFont(be_bold_font);
		badgeFont.SetSize(12.0f);
		SetFont(&badgeFont);
		SetDrawingMode(B_OP_OVER);
		float onew = badgeFont.StringWidth("1");
		font_height fh;
		badgeFont.GetHeight(&fh);
		DrawString("1", BPoint(
			badge.left + (badge.Width() - onew) / 2.0f,
			badge.top + (badge.Height() + fh.ascent - fh.descent) / 2.0f));
		SetDrawingMode(B_OP_COPY);

		// ─── Lifebuoy hanging on the foredeck rail ────────────────────
		float bx = cabinFrontX + 24;
		float by = deckY - 6;
		SetHighColor(kFlagRed);
		FillEllipse(BPoint(bx, by), 5, 5);
		SetHighColor(kHull);
		FillEllipse(BPoint(bx, by), 2, 2);
		SetHighColor(kBlack);
		StrokeEllipse(BPoint(bx, by), 5, 5);

		// ─── Bow mast and lion-of-Venice flag at the prow ─────────────
		SetHighColor(kBlack);
		float mastTop = deckY - 26;
		StrokeLine(BPoint(prowX - 6, deckY - 8), BPoint(prowX - 6, mastTop));
		BPoint flag[] = {
			BPoint(prowX - 6,  mastTop),
			BPoint(prowX + 10, mastTop + 4),
			BPoint(prowX - 6,  mastTop + 8),
		};
		BPolygon flagPoly(flag, 3);
		SetHighColor(kFlagRed);
		FillPolygon(&flagPoly);
		SetHighColor(kBandYellow);
		FillRect(BRect(prowX - 6, mastTop + 1, prowX - 4, mastTop + 7));
		SetHighColor(kBlack);
		StrokePolygon(&flagPoly);

		// ─── Bow wave at the prow ─────────────────────────────────────
		SetHighColor(kWaveCrest);
		for (int i = 0; i < 5; i++) {
			float dx = 10.0f + i * 8.0f;
			StrokeArc(BRect(prowX - 4, wl - 2, prowX + dx, wl + 10),
				200.0f, 70.0f);
		}
	}

	void _DrawCaption(BRect b)
	{
		BFont caption(be_plain_font);
		caption.SetSize(11.0f);
		SetFont(&caption);
		SetHighColor(kCaption);
		SetDrawingMode(B_OP_OVER);
		const char* text = "Buon viaggio in laguna.";
		float w = caption.StringWidth(text);
		DrawString(text, BPoint(b.left + (b.Width() - w) / 2.0f,
			b.bottom - 12));
		SetDrawingMode(B_OP_COPY);
	}
};

}	// namespace


VaporettoWindow::VaporettoWindow()
	:
	BWindow(BRect(120, 140, 720, 420), "Vaporetto",
		B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS | B_QUIT_ON_WINDOW_CLOSE
			| B_CLOSE_ON_ESCAPE)
{
	SetSizeLimits(480, 1400, 240, 800);
	AddChild(new VaporettoView(Bounds()));
}
