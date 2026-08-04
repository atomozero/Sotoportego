/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "AboutWindow.h"

#include <AppFileInfo.h>
#include <Application.h>
#include <Bitmap.h>
#include <Button.h>
#include <File.h>
#include <Font.h>
#include <GradientLinear.h>
#include <LayoutBuilder.h>
#include <Message.h>
#include <Roster.h>
#include <SeparatorView.h>
#include <String.h>
#include <StringView.h>
#include <Url.h>
#include <View.h>

#include "ClickableStringView.h"
#include "HeaderView.h"


static const uint32 kMsgClose = 'clse';
static const uint32 kMsgOpenLink = 'olnk';

static const char* const kProjectUrl = "https://github.com/atomozero/Sotoportego";

// Same palette as the header banner (and as the About window in the author's
// other native Haiku apps), for visual consistency.
static const rgb_color kSlate    = { 40, 50, 65, 255 };
static const rgb_color kSlateTop = { 54, 66, 84, 255 };
static const rgb_color kTitleCol = { 245, 245, 245, 255 };
static const rgb_color kSubCol   = { 180, 195, 210, 255 };
static const rgb_color kTileFill = { 90, 155, 213, 255 };


// "Version X.Y.Z", read from the app_version resource (Sotoportego.rdef) so the
// text always reflects the binary actually built rather than a hand-written
// number that drifts out of sync on the first forgotten release.
static BString
AppVersionText()
{
	BString text;
	app_info info;
	version_info vi;
	if (be_app != NULL && be_app->GetAppInfo(&info) == B_OK) {
		BFile file(&info.ref, B_READ_ONLY);
		BAppFileInfo appInfo(&file);
		if (appInfo.GetVersionInfo(&vi, B_APP_VERSION_KIND) == B_OK) {
			text.SetToFormat("Version %" B_PRIu32 ".%" B_PRIu32 ".%" B_PRIu32,
				vi.major, vi.middle, vi.minor);
		}
	}
	if (text.IsEmpty())
		text = "Version";
	text << "  \xc2\xb7  for Haiku";
	return text;
}


// The banner at the top: app icon on a rounded blue tile, title and version,
// over a vertical gradient -- same drawing as the header banner.
class AboutHero : public BView {
public:
	AboutHero(const char* version)
		:
		BView("hero", B_WILL_DRAW),
		fVersion(version),
		fIcon(HeaderView::MakeLogoBitmap(56))
	{
		SetViewColor(kSlate);
		SetExplicitMinSize(BSize(B_SIZE_UNSET, 104));
		SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, 104));
	}

	virtual ~AboutHero() { delete fIcon; }

	virtual void Draw(BRect)
	{
		BRect b = Bounds();

		BGradientLinear grad(BPoint(0, b.top), BPoint(0, b.bottom));
		grad.AddColor(kSlateTop, 0.0);
		grad.AddColor(kSlate, 255.0);
		FillRect(b, grad);

		float tileSize = 72;
		BRect tile(24, (b.Height() - tileSize) / 2, 24 + tileSize,
			(b.Height() - tileSize) / 2 + tileSize);
		SetHighColor(kTileFill);
		FillRoundRect(tile, 12, 12);
		if (fIcon != NULL) {
			SetDrawingMode(B_OP_ALPHA);
			SetBlendingMode(B_PIXEL_ALPHA, B_ALPHA_OVERLAY);
			float ix = tile.left + (tile.Width() - fIcon->Bounds().Width()) / 2;
			float iy = tile.top + (tile.Height() - fIcon->Bounds().Height()) / 2;
			DrawBitmap(fIcon, BPoint(ix, iy));
			SetDrawingMode(B_OP_OVER);
		}

		float tx = tile.right + 18;
		BFont title(be_bold_font);
		title.SetSize(24);
		SetFont(&title);
		SetHighColor(kTitleCol);
		DrawString("Sotoportego", BPoint(tx, b.Height() / 2 - 2));

		BFont sub(be_plain_font);
		sub.SetSize(12);
		SetFont(&sub);
		SetHighColor(kSubCol);
		DrawString(fVersion.String(), BPoint(tx, b.Height() / 2 + 20));
	}

private:
	BString fVersion;
	BBitmap* fIcon;
};


AboutWindow::AboutWindow()
	:
	BWindow(BRect(0, 0, 460, 320), "About Sotoportego", B_TITLED_WINDOW,
		B_NOT_RESIZABLE | B_NOT_ZOOMABLE | B_AUTO_UPDATE_SIZE_LIMITS)
{
	AboutHero* hero = new AboutHero(AppVersionText().String());

	BStringView* tagline = new BStringView("tagline",
		"A native VPN client for Haiku.");

	BStringView* features = new BStringView("features",
		"OpenVPN \xc2\xb7 WireGuard \xc2\xb7 Tailscale \xc2\xb7 daemon + GUI, CLI "
		"and Deskbar over BMessage");
	BFont small(be_plain_font);
	small.SetSize(be_plain_font->Size() - 1);
	features->SetFont(&small);
	features->SetHighColor(tint_color(ui_color(B_PANEL_TEXT_COLOR), 0.7));

	BStringView* author = new BStringView("author", "by atomozero");
	BFont bold(be_bold_font);
	author->SetFont(&bold);

	ClickableStringView* link = new ClickableStringView("link", kProjectUrl);
	link->SetClickMessage(new BMessage(kMsgOpenLink));

	BStringView* thanks = new BStringView("thanks",
		"Tailscale support built from scratch on the ts2021 protocol \xe2\x80\x94 "
		"no Go, no Rust.");
	thanks->SetFont(&small);
	thanks->SetHighColor(tint_color(ui_color(B_PANEL_TEXT_COLOR), 0.7));

	BStringView* license = new BStringView("license",
		"Distributed under the terms of the MIT License.");
	license->SetFont(&small);
	license->SetHighColor(tint_color(ui_color(B_PANEL_TEXT_COLOR), 0.6));

	BButton* ok = new BButton("ok", "OK", new BMessage(kMsgClose));
	ok->MakeDefault(true);

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.Add(hero)
		.AddGroup(B_VERTICAL, B_USE_SMALL_SPACING)
			.SetInsets(B_USE_WINDOW_INSETS)
			.Add(tagline)
			.Add(features)
			.AddStrut(B_USE_SMALL_SPACING)
			.Add(author)
			.Add(link)
			.AddStrut(B_USE_SMALL_SPACING)
			.Add(thanks)
			.Add(license)
			.AddStrut(B_USE_DEFAULT_SPACING)
			.Add(new BSeparatorView(B_HORIZONTAL))
			.AddGroup(B_HORIZONTAL, 0)
				.AddGlue()
				.Add(ok)
			.End()
		.End();

	// Esc closes just like OK, matching the other utility windows.
	AddShortcut(B_ESCAPE, 0, new BMessage(kMsgClose));
	CenterOnScreen();
}


void
AboutWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgClose:
			Quit();
			break;

		case kMsgOpenLink:
		{
			// Open in the default browser. be_roster->Launch by URL-handler
			// MIME fails on stock Haiku ("Application could not be found"), so
			// resolve the https scheme through BUrl instead.
			BUrl(kProjectUrl, true).OpenWithPreferredApplication(false);
			break;
		}

		default:
			BWindow::MessageReceived(message);
	}
}
