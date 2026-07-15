/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * Adapted from the Sestriere project (also by atomozero), with the
 * Meshtastic contact / SAR-marker code replaced by VPN server pins.
 */
#include "MapView.h"

#include <Bitmap.h>
#include <Directory.h>
#include <File.h>
#include <FindDirectory.h>
#include <Message.h>
#include <Messenger.h>
#include <Path.h>
#include <Window.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

#include "CoastlineData.h"
#include "TileCache.h"


const char* const kFieldHost			= "soto:map:host";
const char* const kClusterHost			= "soto:map:cluster:host";
const char* const kClusterCountryShort	= "soto:map:cluster:countryShort";
const char* const kClusterCountryLong	= "soto:map:cluster:countryLong";
const char* const kClusterLogPolicy		= "soto:map:cluster:logPolicy";
const char* const kClusterPing			= "soto:map:cluster:pingMs";
const char* const kClusterScore			= "soto:map:cluster:score";
const char* const kClusterSessions		= "soto:map:cluster:sessions";


// Zoom levels match Google Maps / OSM standard: fZoom = 256 * 2^z / 360
// Each step doubles/halves the scale (one tile zoom level)
static const int kMinZoomLevel = 2;		// world view
static const int kMaxZoomLevel = 18;	// street level
static const int kDefaultZoomLevel = 13;
static const float kMinFitSpan = 0.01f;	// ~1.1 km minimum visible area


static float
_ZoomForLevel(int level)
{
	// pixels per degree of longitude at this zoom level
	return 256.0f * powf(2.0f, level) / 360.0f;
}


static int
_LevelForZoom(float zoom)
{
	// inverse: z = log2(zoom * 360 / 256)
	int z = (int)roundf(log2f(zoom * 360.0f / 256.0f));
	if (z < kMinZoomLevel) z = kMinZoomLevel;
	if (z > kMaxZoomLevel) z = kMaxZoomLevel;
	return z;
}
static const float kPinRadius = 7.0f;
static const float kSelfRadius = 10.0f;

// Land fill colour for coastlines.
static const rgb_color kLandColor = {60, 75, 55, 255};
static const rgb_color kCoastlineStroke = {90, 110, 80, 255};

// Pin colours per state.
static const rgb_color kPinDefault    = {235, 200, 80, 255};
static const rgb_color kPinHover      = {255, 230, 130, 255};
static const rgb_color kPinSelected   = {255, 100, 100, 255};
static const rgb_color kPinStroke     = {30, 30, 30, 255};


// ============================================================================
// MapView
// ============================================================================

MapView::MapView(const char* name)
	:
	BView(name, B_WILL_DRAW | B_FULL_UPDATE_ON_RESIZE | B_FRAME_EVENTS),
	fPins(20),
	fHasSelfPosition(false),
	fSelfLat(0),
	fSelfLon(0),
	fSelfLabel(),
	fCenterLat(20.0f),
	fCenterLon(0.0f),
	fZoom(_ZoomForLevel(kMinZoomLevel + 1)),	// world-ish view by default
	fDragging(false),
	fDragMoved(false),
	fDragStartLat(0),
	fDragStartLon(0),
	fSelectedPin(NULL),
	fHoverPin(NULL),
	fTileCache(NULL),
	// Default to OSM tiles on: nicer out-of-the-box experience. The
	// offline coastline rendering stays as a fallback for when the cache
	// is empty / the user is offline. LoadMapState() may overwrite both
	// of these from disk on the next line.
	fShowTiles(true),
	fShowCoastlines(true),
	fLastTileZ(-1),
	fLastTileMinX(-1),
	fLastTileMinY(-1),
	fLastTileMaxX(-1),
	fLastTileMaxY(-1)
{
	SetViewColor(B_TRANSPARENT_COLOR);

	// Tile cache lives under the standard cache directory so it survives
	// across Sotoportego runs but is easy to nuke if it gets corrupt.
	BPath cachePath;
	find_directory(B_USER_CACHE_DIRECTORY, &cachePath);
	cachePath.Append("Sotoportego/tiles");
	fTileCache = new TileCache(cachePath.Path());
	fTileCache->Run();
	fTileCache->SetEnabled(fShowTiles);

	// LoadMapState may overwrite fShowTiles + re-call SetEnabled if a
	// previous run saved a different preference.
	LoadMapState();
}


MapView::~MapView()
{
	if (fTileCache != NULL) {
		fTileCache->Lock();
		fTileCache->Quit();
	}
}


void
MapView::AttachedToWindow()
{
	BView::AttachedToWindow();
	SetEventMask(B_POINTER_EVENTS);
}


void
MapView::Draw(BRect /*updateRect*/)
{
	BRect bounds = Bounds();

	// 1. Background - dark blue for "sea"
	SetHighColor(30, 40, 60);
	FillRect(bounds);

	// 2. OSM tiles (if enabled and loaded)
	if (fShowTiles)
		_DrawTiles();

	// 3. Coastlines (always drawn as offline fallback)
	if (fShowCoastlines)
		_DrawCoastlines();

	// 4. Grid (dimmed if tiles active)
	_DrawGrid();

	// 6. Server pins.
	_DrawPins();

	// 6b. Curved arc between self and the active VPN endpoint, if any.
	// Drawn after pins so the arc passes over them, but before _DrawSelf
	// so the "you are here" ring stays the brightest mark on the map.
	_DrawConnectionArc();

	// 7. "You are here" marker if set.
	if (fHasSelfPosition)
		_DrawSelf();

	// 8. Scale bar + compass + cache info.
	_DrawScaleBar();
	_DrawCompass();

	// 9. Tile cache stats + zoom level (bottom-right, small)
	{
		int zLevel = _LevelForZoom(fZoom);
		char info[64];
		if (fShowTiles && fTileCache != NULL) {
			float mb = (float)fTileCache->DiskCacheSize() / (1024 * 1024);
			int32 count = fTileCache->DiskTileCount();
			snprintf(info, sizeof(info), "Z%d  %ld tiles  %.1f/50 MB",
				zLevel, (long)count, mb);
		} else {
			snprintf(info, sizeof(info), "Z%d", zLevel);
		}

		BFont small;
		GetFont(&small);
		small.SetSize(10);
		SetFont(&small);

		float sw = small.StringWidth(info);
		float ix = bounds.Width() - sw - 10;
		float iy = bounds.Height() - 10;

		SetHighColor(0, 0, 0, 140);
		FillRoundRect(BRect(ix - 4, iy - 11, ix + sw + 4, iy + 3), 3, 3);
		SetHighColor(200, 200, 200);
		DrawString(info, BPoint(ix, iy));
	}
}


void
MapView::MouseDown(BPoint where)
{
	int32 buttons;
	if (Window()->CurrentMessage()->FindInt32("buttons", &buttons) != B_OK)
		buttons = B_PRIMARY_MOUSE_BUTTON;

	int32 clicks;
	if (Window()->CurrentMessage()->FindInt32("clicks", &clicks) != B_OK)
		clicks = 1;

	ServerPin* pin = _FindPinAt(where);

	if (buttons & B_PRIMARY_MOUSE_BUTTON) {
		if (clicks == 2 && pin != NULL) {
			// Double-click on a pin re-centres without changing selection.
			fCenterLat = pin->latitude;
			fCenterLon = pin->longitude;
			Invalidate();
		} else if (pin != NULL) {
			if (fSelectedPin != NULL)
				fSelectedPin->selected = false;
			fSelectedPin = pin;
			fSelectedPin->selected = true;
			Invalidate();

			// Tell the host window which server is now selected so the
			// side panel can refresh its details.
			if (Window() != NULL) {
				BMessage out(kMsgServerSelected);
				out.AddString(kFieldHost, pin->host);
				Window()->PostMessage(&out);

				// If this pin is actually the representative of a cluster
				// (>=2 servers rendered onto the same pixel), also emit a
				// kMsgClusterSelected so the main window can offer the
				// drill-down list. The single-pin message above still goes
				// out, so the side panel keeps refreshing as before.
				std::vector<const ServerPin*> members;
				int32 count = _CollectClusterMembers(pin, members);
				if (count > 1) {
					BMessage cluster(kMsgClusterSelected);
					cluster.AddString(kFieldHost, pin->host);
					for (size_t i = 0; i < members.size(); i++) {
						const ServerPin* m = members[i];
						cluster.AddString(kClusterHost, m->host);
						cluster.AddString(kClusterCountryShort,
							m->countryShort);
						cluster.AddString(kClusterCountryLong,
							m->countryLong);
						cluster.AddString(kClusterLogPolicy,
							m->logPolicy);
						cluster.AddInt32(kClusterPing, m->pingMs);
						cluster.AddInt32(kClusterScore, m->score);
						cluster.AddInt32(kClusterSessions, m->sessions);
					}
					Window()->PostMessage(&cluster);
				}
			}
		} else {
			fDragging = true;
			fDragMoved = false;
			fDragStart = where;
			fDragStartLat = fCenterLat;
			fDragStartLon = fCenterLon;
			SetMouseEventMask(B_POINTER_EVENTS, B_LOCK_WINDOW_FOCUS);
		}
	}
}


void
MapView::MouseMoved(BPoint where, uint32 /*transit*/,
	const BMessage* /*dragMessage*/)
{
	if (fDragging) {
		float dx = where.x - fDragStart.x;
		float dy = where.y - fDragStart.y;
		if (dx != 0 || dy != 0)
			fDragMoved = true;

		// In Mercator, longitude is linear but latitude is non-linear.
		// For panning, we compute the Mercator Y difference in screen space.
		float dLon = -dx / fZoom;

		// Convert screen dy back to latitude change via Mercator inverse
		float centerMercY = _MercatorY(fDragStartLat);
		float newMercY = centerMercY + dy / fZoom;

		// Inverse Mercator Y to latitude
		float newLat = atan(sinh(newMercY * M_PI / 180.0f)) * 180.0f / M_PI;

		fCenterLat = newLat;
		fCenterLon = fDragStartLon + dLon;

		if (fCenterLat > 85.0f) fCenterLat = 85.0f;
		if (fCenterLat < -85.0f) fCenterLat = -85.0f;

		Invalidate();
	} else {
		ServerPin* pin = _FindPinAt(where);
		if (pin != fHoverPin) {
			fHoverPin = pin;
			Invalidate();
		}
	}
}


void
MapView::MouseUp(BPoint /*where*/)
{
	fDragging = false;
}


void
MapView::FrameResized(float newWidth, float newHeight)
{
	BView::FrameResized(newWidth, newHeight);
	Invalidate();
}


void
MapView::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case B_MOUSE_WHEEL_CHANGED:
		{
			float deltaY;
			if (message->FindFloat("be:wheel_delta_y", &deltaY) == B_OK) {
				if (deltaY < 0)
					ZoomIn();
				else
					ZoomOut();
			}
			break;
		}

		case MSG_TILES_READY:
		case kMsgZoomIn:
		case kMsgZoomOut:
		case kMsgZoomFit:
		case kMsgCenterSelf:
		case kMsgToggleTiles:
		case kMsgDownloadArea:
			switch (message->what) {
				case MSG_TILES_READY:	Invalidate(); break;
				case kMsgZoomIn:		ZoomIn(); break;
				case kMsgZoomOut:		ZoomOut(); break;
				case kMsgZoomFit:		ZoomToFit(); break;
				case kMsgCenterSelf:	CenterOnSelf(); break;
				case kMsgToggleTiles:	SetTilesEnabled(!fShowTiles); break;
				case kMsgDownloadArea:	DownloadVisibleArea(); break;
			}
			break;

		default:
			BView::MessageReceived(message);
			break;
	}
}


void
MapView::SetSelfPosition(float lat, float lon, const char* label)
{
	bool firstTime = !fHasSelfPosition;

	fSelfLat = lat;
	fSelfLon = lon;
	fSelfLabel = (label != NULL ? label : "");
	fHasSelfPosition = true;

	// Only auto-recenter on the *first* time we learn where we are; later
	// updates (the daemon re-broadcasts on every status change) must not
	// snap the camera away from wherever the user panned to.
	if (firstTime) {
		fCenterLat = lat;
		fCenterLon = lon;
	}

	Invalidate();
}


void
MapView::ClearSelf()
{
	fHasSelfPosition = false;
	fSelfLabel = "";
	Invalidate();
}


void
MapView::SetActiveHost(const BString& host)
{
	if (fActiveHost == host)
		return;
	fActiveHost = host;
	Invalidate();
}


const ServerPin*
MapView::_FindPinByHost(const BString& host) const
{
	if (host.Length() == 0)
		return NULL;
	for (int32 i = 0; i < fPins.CountItems(); i++) {
		const ServerPin* pin = fPins.ItemAt(i);
		if (pin->host == host)
			return pin;
	}
	return NULL;
}


void
MapView::AddServer(const ServerPin& pin)
{
	// Replace by host if we already know about it.
	for (int32 i = 0; i < fPins.CountItems(); i++) {
		ServerPin* existing = fPins.ItemAt(i);
		if (existing->host == pin.host) {
			bool wasSelected = existing->selected;
			*existing = pin;
			existing->selected = wasSelected;
			Invalidate();
			return;
		}
	}
	ServerPin* copy = new ServerPin(pin);
	copy->selected = false;
	fPins.AddItem(copy);
	Invalidate();
}


void
MapView::ClearServers()
{
	fPins.MakeEmpty();
	fSelectedPin = NULL;
	fHoverPin = NULL;
	Invalidate();
}


void
MapView::SetSelectedHost(const BString& host)
{
	for (int32 i = 0; i < fPins.CountItems(); i++) {
		ServerPin* pin = fPins.ItemAt(i);
		if (fSelectedPin == pin)
			pin->selected = false;
		if (pin->host == host) {
			pin->selected = true;
			fSelectedPin = pin;
		}
	}
	Invalidate();
}


const ServerPin*
MapView::SelectedServer() const
{
	return fSelectedPin;
}


void
MapView::ZoomIn()
{
	int level = _LevelForZoom(fZoom);
	if (level < kMaxZoomLevel) {
		fZoom = _ZoomForLevel(level + 1);
		Invalidate();
	}
}


void
MapView::ZoomOut()
{
	int level = _LevelForZoom(fZoom);
	if (level > kMinZoomLevel) {
		fZoom = _ZoomForLevel(level - 1);
		Invalidate();
	}
}


void
MapView::ZoomToFit()
{
	if (fPins.CountItems() == 0 && !fHasSelfPosition)
		return;

	float minLat = 90, maxLat = -90;
	float minLon = 180, maxLon = -180;

	if (fHasSelfPosition) {
		minLat = maxLat = fSelfLat;
		minLon = maxLon = fSelfLon;
	}

	for (int32 i = 0; i < fPins.CountItems(); i++) {
		ServerPin* pin = fPins.ItemAt(i);
		if (pin->latitude < minLat) minLat = pin->latitude;
		if (pin->latitude > maxLat) maxLat = pin->latitude;
		if (pin->longitude < minLon) minLon = pin->longitude;
		if (pin->longitude > maxLon) maxLon = pin->longitude;
	}

	fCenterLat = (minLat + maxLat) / 2.0f;
	fCenterLon = (minLon + maxLon) / 2.0f;

	BRect bounds = Bounds();

	// Ensure minimum visible area
	float lonSpan = std::max(maxLon - minLon, kMinFitSpan);

	// For Mercator, compute Y span in mercator degrees
	float mercMin = _MercatorY(minLat);
	float mercMax = _MercatorY(maxLat);
	float mercSpan = std::max(mercMax - mercMin, kMinFitSpan);

	// fZoom is pixels per degree of longitude
	float zoomLon = (bounds.Width() * 0.7f) / lonSpan;
	float zoomLat = (bounds.Height() * 0.7f) / mercSpan;

	float rawZoom = std::min(zoomLat, zoomLon);
	// Snap to the next zoom level that's at most as tight as the calculated
	// fit. _LevelForZoom rounds to the nearest level, which can pick the
	// finer zoom and crop pins at the edges; floor-rounding here guarantees
	// the chosen zoom is always wide enough to contain all pins (with the
	// 0.7x padding above).
	int level = (int)floorf(log2f(rawZoom * 360.0f / 256.0f));
	if (level < kMinZoomLevel) level = kMinZoomLevel;
	if (level > kMaxZoomLevel) level = kMaxZoomLevel;
	fZoom = _ZoomForLevel(level);

	Invalidate();
}


void
MapView::CenterOnSelf()
{
	if (fHasSelfPosition) {
		fCenterLat = fSelfLat;
		fCenterLon = fSelfLon;
		Invalidate();
	}
}


void
MapView::SetTilesEnabled(bool enabled)
{
	fShowTiles = enabled;
	if (fTileCache != NULL)
		fTileCache->SetEnabled(enabled);
	Invalidate();
}


void
MapView::SaveMapState()
{
	BPath settingsPath;
	find_directory(B_USER_SETTINGS_DIRECTORY, &settingsPath);
	settingsPath.Append("Sotoportego");
	create_directory(settingsPath.Path(), 0755);
	settingsPath.Append("map.settings");

	FILE* fp = fopen(settingsPath.Path(), "w");
	if (fp == NULL)
		return;

	fprintf(fp, "center_lat=%.6f\n", fCenterLat);
	fprintf(fp, "center_lon=%.6f\n", fCenterLon);
	fprintf(fp, "zoom=%.2f\n", fZoom);
	fprintf(fp, "tiles=%d\n", fShowTiles ? 1 : 0);
	fclose(fp);
}


void
MapView::LoadMapState()
{
	BPath settingsPath;
	find_directory(B_USER_SETTINGS_DIRECTORY, &settingsPath);
	settingsPath.Append("Sotoportego/map.settings");

	FILE* fp = fopen(settingsPath.Path(), "r");
	if (fp == NULL)
		return;

	char line[128];
	while (fgets(line, sizeof(line), fp) != NULL) {
		double val;
		int ival;
		if (sscanf(line, "center_lat=%lf", &val) == 1) {
			if (val >= -85.0 && val <= 85.0)
				fCenterLat = (float)val;
		} else if (sscanf(line, "center_lon=%lf", &val) == 1) {
			if (val >= -180.0 && val <= 180.0)
				fCenterLon = (float)val;
		} else if (sscanf(line, "zoom=%lf", &val) == 1) {
			float minZoom = _ZoomForLevel(kMinZoomLevel);
			float maxZoom = _ZoomForLevel(kMaxZoomLevel);
			if (val >= minZoom && val <= maxZoom)
				fZoom = (float)val;
		} else if (sscanf(line, "tiles=%d", &ival) == 1) {
			fShowTiles = (ival != 0);
			if (fTileCache != NULL)
				fTileCache->SetEnabled(fShowTiles);
		}
	}
	fclose(fp);
}


void
MapView::DownloadVisibleArea()
{
	if (fTileCache == NULL || !fTileCache->IsEnabled())
		return;

	int tileZ = _ZoomToTileZoom();
	BRect bounds = Bounds();
	float width = bounds.Width();
	float height = bounds.Height();

	// Calculate lat/lon bounds of visible area
	float lonPerPx = 1.0f / fZoom;
	float latPerPx = lonPerPx;  // Approximation at equator

	float minLon = fCenterLon - (width / 2.0f) * lonPerPx;
	float maxLon = fCenterLon + (width / 2.0f) * lonPerPx;
	float minLat = fCenterLat - (height / 2.0f) * latPerPx;
	float maxLat = fCenterLat + (height / 2.0f) * latPerPx;

	// Download current zoom level and one level below
	int minZ = (tileZ > 2) ? tileZ - 1 : tileZ;
	int maxZ = (tileZ < 18) ? tileZ + 1 : tileZ;

	int32 totalTiles = 0;
	for (int z = minZ; z <= maxZ; z++) {
		int n = 1 << z;
		int xMin = (int)((minLon + 180.0) / 360.0 * n);
		int xMax = (int)((maxLon + 180.0) / 360.0 * n);
		int yMin = (int)((1.0 - log(tan(minLat * M_PI / 180.0)
			+ 1.0 / cos(minLat * M_PI / 180.0)) / M_PI)
			/ 2.0 * n);
		int yMax = (int)((1.0 - log(tan(maxLat * M_PI / 180.0)
			+ 1.0 / cos(maxLat * M_PI / 180.0)) / M_PI)
			/ 2.0 * n);

		// Swap if needed (y axis is inverted in tile coords)
		if (yMin > yMax) {
			int tmp = yMin;
			yMin = yMax;
			yMax = tmp;
		}

		// Clamp
		if (xMin < 0) xMin = 0;
		if (xMax >= n) xMax = n - 1;
		if (yMin < 0) yMin = 0;
		if (yMax >= n) yMax = n - 1;

		totalTiles += (xMax - xMin + 1) * (yMax - yMin + 1);

		fTileCache->RequestTiles(z, xMin, yMin, xMax, yMax, this);
	}

	fprintf(stderr, "[MapView] Downloading ~%d tiles for visible area "
		"(Z%d-%d)\n", (int)totalTiles, minZ, maxZ);
}


// ============================================================================
// Mercator projection
// ============================================================================

/*static*/ float
MapView::_MercatorY(float latDeg)
{
	// Clamp to avoid infinity at poles
	if (latDeg > 85.051f) latDeg = 85.051f;
	if (latDeg < -85.051f) latDeg = -85.051f;

	float latRad = latDeg * M_PI / 180.0f;
	return log(tan(M_PI / 4.0f + latRad / 2.0f)) * (180.0f / M_PI);
}


BPoint
MapView::_LatLonToScreen(float lat, float lon) const
{
	BRect bounds = Bounds();
	float centerX = bounds.Width() / 2.0f;
	float centerY = bounds.Height() / 2.0f;

	// fZoom = pixels per degree of longitude
	float x = centerX + (lon - fCenterLon) * fZoom;
	float y = centerY - (_MercatorY(lat) - _MercatorY(fCenterLat)) * fZoom;

	return BPoint(x, y);
}


void
MapView::_ScreenToLatLon(BPoint screen, float& lat, float& lon) const
{
	BRect bounds = Bounds();
	float centerX = bounds.Width() / 2.0f;
	float centerY = bounds.Height() / 2.0f;

	lon = fCenterLon + (screen.x - centerX) / fZoom;

	float mercY = _MercatorY(fCenterLat) - (screen.y - centerY) / fZoom;
	// Inverse Mercator: lat = atan(sinh(mercY * pi / 180)) * 180 / pi
	lat = atan(sinh(mercY * M_PI / 180.0f)) * 180.0f / M_PI;
}


// ============================================================================
// Tile drawing
// ============================================================================

int
MapView::_ZoomToTileZoom() const
{
	// fZoom is snapped to discrete levels, so this is a direct conversion.
	// Clamp to OSM tile range (tiles available up to z=17).
	int tileZ = _LevelForZoom(fZoom);
	if (tileZ > 17) tileZ = 17;
	return tileZ;
}


void
MapView::_DrawTiles()
{
	if (fTileCache == NULL || !fShowTiles)
		return;

	BRect bounds = Bounds();
	int tileZ = _ZoomToTileZoom();
	int numTiles = 1 << tileZ;

	// Get visible area in lat/lon
	float topLat, leftLon, botLat, rightLon;
	_ScreenToLatLon(BPoint(0, 0), topLat, leftLon);
	_ScreenToLatLon(BPoint(bounds.Width(), bounds.Height()), botLat, rightLon);

	// Convert to tile coords
	// tile x = floor((lon + 180) / 360 * 2^z)
	int minTileX = (int)floor((leftLon + 180.0f) / 360.0f * numTiles);
	int maxTileX = (int)floor((rightLon + 180.0f) / 360.0f * numTiles);

	// tile y = floor((1 - ln(tan(lat) + sec(lat)) / pi) / 2 * 2^z)
	float latRadTop = topLat * M_PI / 180.0f;
	float latRadBot = botLat * M_PI / 180.0f;

	int minTileY = (int)floor((1.0f - log(tan(latRadTop) +
		1.0f / cos(latRadTop)) / M_PI) / 2.0f * numTiles);
	int maxTileY = (int)floor((1.0f - log(tan(latRadBot) +
		1.0f / cos(latRadBot)) / M_PI) / 2.0f * numTiles);

	// Clamp
	if (minTileX < 0) minTileX = 0;
	if (maxTileX >= numTiles) maxTileX = numTiles - 1;
	if (minTileY < 0) minTileY = 0;
	if (maxTileY >= numTiles) maxTileY = numTiles - 1;

	// Draw cached tiles
	for (int tx = minTileX; tx <= maxTileX; tx++) {
		for (int ty = minTileY; ty <= maxTileY; ty++) {
			// Tile top-left corner in lat/lon
			float tileLon = (float)tx * 360.0f / numTiles - 180.0f;
			float n = M_PI - 2.0f * M_PI * ty / numTiles;
			float tileLat = 180.0f / M_PI * atan(0.5f *
				(exp(n) - exp(-n)));

			// Tile bottom-right
			float nextLon = (float)(tx + 1) * 360.0f / numTiles - 180.0f;
			float n2 = M_PI - 2.0f * M_PI * (ty + 1) / numTiles;
			float nextLat = 180.0f / M_PI * atan(0.5f *
				(exp(n2) - exp(-n2)));

			BPoint topLeft = _LatLonToScreen(tileLat, tileLon);
			BPoint botRight = _LatLonToScreen(nextLat, nextLon);

			BRect destRect(topLeft.x, topLeft.y, botRight.x, botRight.y);
			// DrawTile does the lookup and the DrawBitmap under the cache
			// lock (see TileCache::DrawTile); a missing tile just draws
			// nothing. This closes the use-after-free window where the
			// looper thread's _PruneMemoryCache() could free a bitmap
			// while we were mid-draw.
			fTileCache->DrawTile(this, tileZ, tx, ty, destRect);
		}
	}

	// Request tiles async (if visible range changed)
	if (tileZ != fLastTileZ || minTileX != fLastTileMinX
		|| minTileY != fLastTileMinY || maxTileX != fLastTileMaxX
		|| maxTileY != fLastTileMaxY) {
		fLastTileZ = tileZ;
		fLastTileMinX = minTileX;
		fLastTileMinY = minTileY;
		fLastTileMaxX = maxTileX;
		fLastTileMaxY = maxTileY;

		fTileCache->RequestTiles(tileZ, minTileX, minTileY,
			maxTileX, maxTileY, this);
	}
}


// ============================================================================
// Coastline drawing
// ============================================================================

void
MapView::_DrawCoastlines()
{
	if (fShowTiles) {
		// When tiles are active, draw thin coastline outlines only
		SetHighColor(kCoastlineStroke);
		SetPenSize(1.0f);
	} else {
		// No tiles: fill land polygons
		SetHighColor(kLandColor);
	}

	// Walk through coastline data drawing polylines
	int i = 0;
	while (i < kCoastlinePointCount) {
		float lat = kCoastlineData[i * 2];
		float lon = kCoastlineData[i * 2 + 1];

		if (lat >= 998.0f && lon >= 998.0f) {
			// Sentinel — skip
			i++;
			continue;
		}

		// Collect polyline points until next sentinel
		BPoint polyPoints[256];
		int pointCount = 0;

		while (i < kCoastlinePointCount && pointCount < 256) {
			lat = kCoastlineData[i * 2];
			lon = kCoastlineData[i * 2 + 1];

			if (lat >= 998.0f && lon >= 998.0f) {
				i++;
				break;
			}

			polyPoints[pointCount] = _LatLonToScreen(lat, lon);
			pointCount++;
			i++;
		}

		if (pointCount < 2)
			continue;

		if (fShowTiles) {
			// Just stroke the outline
			for (int p = 0; p < pointCount - 1; p++)
				StrokeLine(polyPoints[p], polyPoints[p + 1]);
		} else {
			// Fill the polygon for land
			if (pointCount >= 3) {
				SetHighColor(kLandColor);
				FillPolygon(polyPoints, pointCount);
			}
			// Stroke the outline
			SetHighColor(kCoastlineStroke);
			SetPenSize(1.0f);
			for (int p = 0; p < pointCount - 1; p++)
				StrokeLine(polyPoints[p], polyPoints[p + 1]);
		}
	}

	SetPenSize(1.0f);
}


void
MapView::_DrawGrid()
{
	BRect bounds = Bounds();

	float minLat, maxLat, minLon, maxLon;
	_ScreenToLatLon(BPoint(0, bounds.Height()), minLat, minLon);
	_ScreenToLatLon(BPoint(bounds.Width(), 0), maxLat, maxLon);

	// Adaptive spacing: maintain ~50-120px between grid lines at all zoom levels
	float gridSpacing;
	if (fZoom > 50000) gridSpacing = 0.001f;
	else if (fZoom > 10000) gridSpacing = 0.01f;
	else if (fZoom > 1000) gridSpacing = 0.1f;
	else if (fZoom > 500) gridSpacing = 0.5f;
	else if (fZoom > 100) gridSpacing = 1.0f;
	else if (fZoom > 40) gridSpacing = 2.0f;
	else if (fZoom > 20) gridSpacing = 5.0f;
	else if (fZoom > 8) gridSpacing = 10.0f;
	else if (fZoom > 4) gridSpacing = 15.0f;
	else gridSpacing = 30.0f;

	// Theme-aware grid color
	rgb_color panelBg = ui_color(B_PANEL_BACKGROUND_COLOR);
	rgb_color gridColor = tint_color(panelBg, B_DARKEN_2_TINT);
	gridColor.alpha = fShowTiles ? 60 : 120;
	SetHighColor(gridColor);
	SetDrawingMode(B_OP_ALPHA);
	SetPenSize(1.0f);

	float startLat = floor(minLat / gridSpacing) * gridSpacing;
	for (float lat = startLat; lat <= maxLat; lat += gridSpacing) {
		BPoint p1 = _LatLonToScreen(lat, minLon);
		BPoint p2 = _LatLonToScreen(lat, maxLon);
		StrokeLine(p1, p2);
	}

	float startLon = floor(minLon / gridSpacing) * gridSpacing;
	for (float lon = startLon; lon <= maxLon; lon += gridSpacing) {
		BPoint p1 = _LatLonToScreen(minLat, lon);
		BPoint p2 = _LatLonToScreen(maxLat, lon);
		StrokeLine(p1, p2);
	}

	// Coordinate labels on grid edges
	BFont labelFont(be_plain_font);
	labelFont.SetSize(9.0f);
	SetFont(&labelFont);
	font_height fh;
	labelFont.GetHeight(&fh);
	float fontAscent = fh.ascent;
	float fontHeight = fh.ascent + fh.descent;

	rgb_color labelBg = panelBg;
	labelBg.alpha = 180;
	rgb_color textColor = tint_color(panelBg, B_DARKEN_MAX_TINT);

	const float kLabelPadH = 2.0f;
	const float kLabelPadV = 1.0f;
	const float kLabelMargin = 3.0f;

	// Latitude labels on left edge
	for (float lat = startLat; lat <= maxLat; lat += gridSpacing) {
		BPoint screenPt = _LatLonToScreen(lat, minLon);
		float y = screenPt.y;
		if (y < fontHeight || y > bounds.Height() - kLabelMargin)
			continue;

		char label[16];
		float absLat = fabsf(lat);
		if (gridSpacing >= 1.0f)
			snprintf(label, sizeof(label), "%d°%s", (int)absLat,
				lat > 0 ? "N" : (lat < 0 ? "S" : ""));
		else
			snprintf(label, sizeof(label), "%.1f°%s", absLat,
				lat > 0 ? "N" : (lat < 0 ? "S" : ""));

		float labelWidth = labelFont.StringWidth(label);
		BRect bg(kLabelMargin, y - fontAscent - kLabelPadV,
			kLabelMargin + labelWidth + 2 * kLabelPadH,
			y + fh.descent + kLabelPadV);
		SetHighColor(labelBg);
		FillRect(bg);
		SetHighColor(textColor);
		DrawString(label, BPoint(kLabelMargin + kLabelPadH, y));
	}

	// Longitude labels on bottom edge
	for (float lon = startLon; lon <= maxLon; lon += gridSpacing) {
		BPoint screenPt = _LatLonToScreen(maxLat, lon);
		float x = screenPt.x;

		char label[16];
		float absLon = fabsf(lon);
		if (gridSpacing >= 1.0f)
			snprintf(label, sizeof(label), "%d°%s", (int)absLon,
				lon > 0 ? "E" : (lon < 0 ? "W" : ""));
		else
			snprintf(label, sizeof(label), "%.1f°%s", absLon,
				lon > 0 ? "E" : (lon < 0 ? "W" : ""));

		float labelWidth = labelFont.StringWidth(label);
		if (x < kLabelMargin || x + labelWidth > bounds.Width() - kLabelMargin)
			continue;

		float labelY = bounds.Height() - kLabelMargin - fh.descent;
		BRect bg(x - kLabelPadH, labelY - fontAscent - kLabelPadV,
			x + labelWidth + kLabelPadH,
			labelY + fh.descent + kLabelPadV);
		SetHighColor(labelBg);
		FillRect(bg);
		SetHighColor(textColor);
		DrawString(label, BPoint(x, labelY));
	}

	SetDrawingMode(B_OP_COPY);
}


void
MapView::_DrawPins()
{
	// Group pins by integer screen position so the country-centroid
	// fallback (every server in a country at the same lat/lon) draws as a
	// single cluster pin with a count badge instead of N overlapping dots.
	// The representative of each cluster is the highest-scored server, and
	// the cluster inherits "selected" / "hover" highlighting from any
	// member.
	struct Cluster {
		BPoint		pos;
		int32		repIndex;	// pin chosen as the badge target
		int32		count;
		bool		selected;
		bool		hover;
	};
	std::vector<Cluster> clusters;

	for (int32 i = 0; i < fPins.CountItems(); i++) {
		const ServerPin* pin = fPins.ItemAt(i);
		BPoint pos = _LatLonToScreen(pin->latitude, pin->longitude);
		// Snap to integer pixels so floating-point noise can't split what
		// the eye reads as the same point.
		int32 rx = (int32)floorf(pos.x + 0.5f);
		int32 ry = (int32)floorf(pos.y + 0.5f);

		Cluster* found = NULL;
		for (size_t c = 0; c < clusters.size(); c++) {
			if ((int32)floorf(clusters[c].pos.x + 0.5f) == rx
					&& (int32)floorf(clusters[c].pos.y + 0.5f) == ry) {
				found = &clusters[c];
				break;
			}
		}

		if (found == NULL) {
			Cluster fresh;
			fresh.pos = pos;
			fresh.repIndex = i;
			fresh.count = 1;
			fresh.selected = pin->selected;
			fresh.hover = (pin == fHoverPin);
			clusters.push_back(fresh);
		} else {
			found->count++;
			if (pin->selected)
				found->selected = true;
			if (pin == fHoverPin)
				found->hover = true;
			const ServerPin* current = fPins.ItemAt(found->repIndex);
			if (pin->score > current->score)
				found->repIndex = i;
		}
	}

	for (size_t c = 0; c < clusters.size(); c++) {
		const Cluster& cluster = clusters[c];
		const ServerPin* rep = fPins.ItemAt(cluster.repIndex);

		// Synthesise the representative's flags so a cluster picks up the
		// highlighting state from any member without mutating the pins.
		ServerPin shadow = *rep;
		shadow.selected = cluster.selected;
		_DrawPin(shadow, cluster.count);
	}
}


void
MapView::_DrawPin(const ServerPin& pin, int count)
{
	BPoint pos = _LatLonToScreen(pin.latitude, pin.longitude);
	BRect bounds = Bounds();
	if (pos.x < -20 || pos.x > bounds.Width() + 20
			|| pos.y < -20 || pos.y > bounds.Height() + 20) {
		return;
	}

	float radius = kPinRadius;
	rgb_color fill = kPinDefault;
	if (pin.selected) {
		fill = kPinSelected;
		radius += 2;
	} else if (&pin == fHoverPin) {
		fill = kPinHover;
		radius += 1;
	}

	// Clusters of more than one server grow with the count so they read as
	// a "many" affordance even from far away. The growth is sub-linear so
	// 50 servers don't blot out the country they're in.
	if (count > 1)
		radius += std::min(6.0f, 1.5f * log2f((float)count));

	// White outer halo so the pin stays readable on any tile colour.
	SetHighColor(255, 255, 255, 255);
	FillEllipse(pos, radius + 2, radius + 2);

	SetHighColor(fill);
	FillEllipse(pos, radius, radius);

	SetHighColor(kPinStroke);
	StrokeEllipse(pos, radius, radius);

	if (count > 1) {
		// Count label centred on the pin. Bold and dark so it stays
		// legible against the pin fill colours.
		char buf[16];
		snprintf(buf, sizeof(buf), "%d", count);

		BFont font(be_bold_font);
		font.SetSize(radius < 12.0f ? 9.0f : 11.0f);
		SetFont(&font);

		font_height fh;
		font.GetHeight(&fh);
		float textWidth = font.StringWidth(buf);

		SetHighColor(kPinStroke);
		SetDrawingMode(B_OP_OVER);
		DrawString(buf,
			BPoint(pos.x - textWidth / 2.0f,
				pos.y + (fh.ascent - fh.descent) / 2.0f));
		SetDrawingMode(B_OP_COPY);
	}
}


void
MapView::_DrawSelf()
{
	if (!fHasSelfPosition)
		return;
	BPoint pos = _LatLonToScreen(fSelfLat, fSelfLon);

	// Concentric "you are here" ring.
	SetHighColor(80, 180, 255, 200);
	FillEllipse(pos, kSelfRadius, kSelfRadius);
	SetHighColor(255, 255, 255);
	SetPenSize(2.0f);
	StrokeEllipse(pos, kSelfRadius, kSelfRadius);
	SetPenSize(1.0f);

	if (fSelfLabel.Length() > 0) {
		BFont font(be_plain_font);
		font.SetSize(10.0f);
		SetFont(&font);
		float w = font.StringWidth(fSelfLabel.String());
		BPoint labelPos(pos.x - w / 2.0f, pos.y + kSelfRadius + 12.0f);
		SetHighColor(0, 0, 0, 180);
		FillRoundRect(BRect(labelPos.x - 2, labelPos.y - 10,
			labelPos.x + w + 2, labelPos.y + 2), 3, 3);
		SetHighColor(255, 255, 255);
		DrawString(fSelfLabel.String(), labelPos);
	}
}


void
MapView::_DrawConnectionArc()
{
	if (!fHasSelfPosition)
		return;
	const ServerPin* target = _FindPinByHost(fActiveHost);
	if (target == NULL)
		return;

	BPoint a = _LatLonToScreen(fSelfLat, fSelfLon);
	BPoint b = _LatLonToScreen(target->latitude, target->longitude);

	float dx = b.x - a.x;
	float dy = b.y - a.y;
	float length = sqrtf(dx * dx + dy * dy);
	if (length < 1.0f)
		return;

	// Bulge the curve toward the top of the screen by a fraction of the
	// chord length, scaled by the longitude span so short hops stay nearly
	// straight and trans-oceanic hops get a clear arc.
	BPoint mid((a.x + b.x) * 0.5f, (a.y + b.y) * 0.5f);
	float nx = -dy / length;
	float ny =  dx / length;
	if (ny > 0) {	// pick the perpendicular that points "up" on screen
		nx = -nx;
		ny = -ny;
	}
	float bulge = length * 0.18f;
	BPoint ctrl(mid.x + nx * bulge, mid.y + ny * bulge);

	// Two-pass stroke: a wide soft glow underneath, then a thinner solid
	// line on top. Matches the look of the self-position ring so the eye
	// reads the pair as belonging to one mark.
	SetDrawingMode(B_OP_ALPHA);
	SetBlendingMode(B_PIXEL_ALPHA, B_ALPHA_OVERLAY);

	const int kSegments = 28;
	BPoint prev = a;
	BPoint pts[kSegments + 1];
	pts[0] = a;
	for (int i = 1; i <= kSegments; i++) {
		float t = (float)i / (float)kSegments;
		float u = 1.0f - t;
		pts[i].x = u * u * a.x + 2 * u * t * ctrl.x + t * t * b.x;
		pts[i].y = u * u * a.y + 2 * u * t * ctrl.y + t * t * b.y;
	}

	SetHighColor(80, 180, 255, 70);
	SetPenSize(6.0f);
	prev = pts[0];
	for (int i = 1; i <= kSegments; i++) {
		StrokeLine(prev, pts[i]);
		prev = pts[i];
	}

	SetHighColor(80, 180, 255, 230);
	SetPenSize(2.0f);
	prev = pts[0];
	for (int i = 1; i <= kSegments; i++) {
		StrokeLine(prev, pts[i]);
		prev = pts[i];
	}

	// Small filled arrowhead at the server end, oriented along the last
	// curve segment.
	BPoint tip = pts[kSegments];
	BPoint tail = pts[kSegments - 1];
	float vx = tip.x - tail.x;
	float vy = tip.y - tail.y;
	float vlen = sqrtf(vx * vx + vy * vy);
	if (vlen > 0.001f) {
		vx /= vlen;
		vy /= vlen;
		// Perpendicular for the arrowhead base.
		float px = -vy;
		float py =  vx;
		const float head = 9.0f;
		const float halfWidth = 4.5f;
		BPoint base(tip.x - vx * head, tip.y - vy * head);
		BPoint left(base.x + px * halfWidth, base.y + py * halfWidth);
		BPoint right(base.x - px * halfWidth, base.y - py * halfWidth);
		BPoint triangle[3] = { tip, left, right };
		SetHighColor(80, 180, 255, 230);
		FillPolygon(triangle, 3);
	}

	SetPenSize(1.0f);

	// Destination label: the long country name (e.g. "Japan") in a small
	// dark pill below the target pin, matching the self-position label so
	// the two read as a pair. Falls back to the ISO-2 code if the long
	// name is missing, then to the host as a last resort.
	BString destLabel;
	if (target->countryLong.Length() > 0)
		destLabel = target->countryLong;
	else if (target->countryShort.Length() > 0)
		destLabel = target->countryShort;
	else
		destLabel = target->host;

	if (destLabel.Length() > 0) {
		BFont labelFont(be_plain_font);
		labelFont.SetSize(10.0f);
		SetFont(&labelFont);

		float w = labelFont.StringWidth(destLabel.String());
		// 25px below the target pin clears both the pin itself and the
		// cluster count badge when the destination happens to be the
		// representative of a multi-server cluster.
		BPoint labelPos(b.x - w / 2.0f, b.y + 25.0f);
		SetHighColor(0, 0, 0, 180);
		FillRoundRect(BRect(labelPos.x - 4, labelPos.y - 10,
			labelPos.x + w + 4, labelPos.y + 3), 3, 3);
		SetHighColor(255, 255, 255);
		DrawString(destLabel.String(), labelPos);
	}

	SetDrawingMode(B_OP_COPY);
}


void
MapView::_DrawScaleBar()
{
	BRect bounds = Bounds();

	// At the equator, 1 degree lon ≈ 111km.
	// fZoom = pixels per degree lon, so metersPerPixel ≈ 111000 / fZoom
	float metersPerPixel = 111000.0f / fZoom;
	float targetPixels = 100.0f;
	float targetMeters = metersPerPixel * targetPixels;

	float scale;
	const char* unit;
	if (targetMeters >= 1000) {
		scale = floor(targetMeters / 1000.0f);
		if (scale < 1) scale = 1;
		unit = "km";
		targetMeters = scale * 1000;
	} else {
		scale = floor(targetMeters / 100.0f) * 100;
		if (scale < 100) scale = 100;
		unit = "m";
		targetMeters = scale;
	}

	float barPixels = targetMeters / metersPerPixel;

	float x = 20;
	float y = bounds.Height() - 30;

	SetHighColor(255, 255, 255);
	SetPenSize(2.0f);
	StrokeLine(BPoint(x, y), BPoint(x + barPixels, y));
	StrokeLine(BPoint(x, y - 5), BPoint(x, y + 5));
	StrokeLine(BPoint(x + barPixels, y - 5), BPoint(x + barPixels, y + 5));
	SetPenSize(1.0f);

	char label[32];
	snprintf(label, sizeof(label), "%.0f %s", scale, unit);
	DrawString(label, BPoint(x + barPixels / 2 - 15, y - 8));
}


void
MapView::_DrawCompass()
{
	BRect bounds = Bounds();
	float cx = bounds.Width() - 40;
	float cy = 40;
	float size = 20;

	SetHighColor(255, 255, 255);
	SetPenSize(2.0f);

	StrokeLine(BPoint(cx, cy - size), BPoint(cx, cy + size));
	StrokeLine(BPoint(cx - size, cy), BPoint(cx + size, cy));

	// North arrow
	SetHighColor(255, 0, 0);
	FillTriangle(BPoint(cx, cy - size),
		BPoint(cx - 5, cy - size + 10),
		BPoint(cx + 5, cy - size + 10));

	SetHighColor(255, 255, 255);
	DrawString("N", BPoint(cx - 4, cy - size - 5));

	SetPenSize(1.0f);
}


ServerPin*
MapView::_FindPinAt(BPoint where)
{
	float radius = kPinRadius + 5;

	// With country-centroid geocoding many pins land on the same screen
	// position; collect every hit and return the highest-scored one so a
	// click on the cluster picks the server the user most likely wants.
	ServerPin* best = NULL;
	for (int32 i = fPins.CountItems() - 1; i >= 0; i--) {
		ServerPin* pin = fPins.ItemAt(i);
		BPoint pos = _LatLonToScreen(pin->latitude, pin->longitude);
		float dx = where.x - pos.x;
		float dy = where.y - pos.y;
		if (sqrt(dx * dx + dy * dy) > radius)
			continue;
		if (best == NULL || pin->score > best->score)
			best = pin;
	}

	return best;
}


int32
MapView::_CollectClusterMembers(const ServerPin* representative,
	std::vector<const ServerPin*>& out) const
{
	if (representative == NULL)
		return 0;

	// Use the same pixel-rounding rule as _DrawPins so clusters here and
	// clusters drawn on screen agree on membership.
	BPoint repPos = _LatLonToScreen(representative->latitude,
		representative->longitude);
	int32 rx = (int32)floorf(repPos.x + 0.5f);
	int32 ry = (int32)floorf(repPos.y + 0.5f);

	out.clear();
	for (int32 i = 0; i < fPins.CountItems(); i++) {
		const ServerPin* pin = fPins.ItemAt(i);
		BPoint pos = _LatLonToScreen(pin->latitude, pin->longitude);
		if ((int32)floorf(pos.x + 0.5f) == rx
				&& (int32)floorf(pos.y + 0.5f) == ry) {
			out.push_back(pin);
		}
	}

	return (int32)out.size();
}

