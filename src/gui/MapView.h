/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * MapView -- pan/zoom world map with VPN server pins. Adapted from the
 * Sestriere project (also by atomozero), with the Meshtastic-specific
 * contact / SAR-marker machinery stripped out.
 */
#ifndef MAP_VIEW_H
#define MAP_VIEW_H


#include <vector>

#include <View.h>

#include "Compat.h"

class BBitmap;
class TileCache;


// Toolbar message codes; wired by the host window to the buttons it
// surfaces.
enum {
	kMsgZoomIn			= 'mvZi',
	kMsgZoomOut			= 'mvZo',
	kMsgZoomFit			= 'mvZf',
	kMsgCenterSelf		= 'mvCs',
	kMsgToggleTiles		= 'mvTt',
	kMsgDownloadArea	= 'mvDa',
	// Sent to the host window when the user clicks a server pin. Carries
	// kFieldHost (string).
	kMsgServerSelected	= 'mvSs',
	// Sent when the user clicks a cluster (a pin badge whose count > 1).
	// Carries one repeated entry per cluster member under each kCluster*
	// field below, in the same order, so the side panel / main window can
	// list them and let the user pick one. The "representative" host (the
	// highest-scored pin in the cluster, same one MouseDown would have
	// selected before this commit) is also added under kFieldHost so the
	// existing single-pin selection path still fires alongside.
	kMsgClusterSelected	= 'mvSc'
};


// BMessage field names used by kMsgServerSelected / kMsgClusterSelected.
extern const char* const kFieldHost;
extern const char* const kClusterHost;
extern const char* const kClusterCountryShort;
extern const char* const kClusterCountryLong;
extern const char* const kClusterLogPolicy;
extern const char* const kClusterPing;
extern const char* const kClusterScore;
extern const char* const kClusterSessions;


// One VPN server placed on the map. The host string is the canonical
// identifier; the rest is presentation/sort metadata that the side panel
// shows when the pin is selected.
struct ServerPin {
	BString		host;
	BString		countryShort;	// ISO-2 code, e.g. "JP"
	BString		countryLong;	// human name, e.g. "Japan"
	BString		logPolicy;		// vpngate LogType field
	float		latitude;
	float		longitude;
	int32		score;			// vpngate score, higher = better
	int32		pingMs;
	int32		speedMbps;
	int32		sessions;
	bool		selected;

	ServerPin()
		:
		latitude(0), longitude(0),
		score(0), pingMs(0), speedMbps(0), sessions(0),
		selected(false)
	{
	}
};


class MapView : public BView {
public:
								MapView(const char* name);
	virtual						~MapView();

	virtual	void				AttachedToWindow();
	virtual	void				Draw(BRect updateRect);
	virtual	void				MouseDown(BPoint where);
	virtual	void				MouseMoved(BPoint where, uint32 transit,
									const BMessage* dragMessage);
	virtual	void				MouseUp(BPoint where);
	virtual	void				FrameResized(float newWidth, float newHeight);
	virtual	void				MessageReceived(BMessage* message);

	// Pin set management. AddServer keys by host; passing the same host
	// twice replaces the previous entry.
			void				AddServer(const ServerPin& pin);
			void				ClearServers();
			void				SetSelectedHost(const BString& host);
			const ServerPin*	SelectedServer() const;

	// "You are here" marker. Wired to the daemon's home geo-lookup: the
	// daemon resolves where our underlying carrier puts us and pushes the
	// values into kFieldHomeLat/kFieldHomeLon in every status broadcast,
	// VPNMapWindow plumbs them into here.
			void				SetSelfPosition(float lat, float lon,
									const char* label);
			void				ClearSelf();

	// Tell the map which server pin is currently the live VPN endpoint, so
	// it can draw a "connection arc" between SelfPosition and that pin.
	// Pass an empty string to clear the active host (e.g. on disconnect).
	// Unknown hosts are stored but ignored at draw time; calling
	// SetActiveHost before AddServer is therefore safe.
			void				SetActiveHost(const BString& host);

			void				ZoomIn();
			void				ZoomOut();
			void				ZoomToFit();
			void				CenterOnSelf();

			void				SetTilesEnabled(bool enabled);
			bool				TilesEnabled() const { return fShowTiles; }

			void				SaveMapState();
			void				LoadMapState();
			void				DownloadVisibleArea();

private:
	// Mercator projection helpers.
	static	float				_MercatorY(float latDeg);
			BPoint				_LatLonToScreen(float lat, float lon) const;
			void				_ScreenToLatLon(BPoint screen, float& lat,
									float& lon) const;

			void				_DrawTiles();
			void				_DrawCoastlines();
			void				_DrawGrid();
			void				_DrawPins();
	// Draw a single pin (count == 1) or a cluster (count > 1, with the
	// count badged on top of `representative` -- typically the highest-
	// scored server in the cluster).
			void				_DrawPin(const ServerPin& representative,
									int count = 1);
			void				_DrawSelf();
			void				_DrawConnectionArc();
			void				_DrawScaleBar();
			void				_DrawCompass();

			const ServerPin*	_FindPinByHost(const BString& host) const;

			ServerPin*			_FindPinAt(BPoint where);
	// Populate `out` with every pin whose screen-rounded position lands
	// on the same pixel as `representative`. Used by MouseDown to detect
	// cluster clicks. Returns the number of members appended.
			int32				_CollectClusterMembers(
									const ServerPin* representative,
									std::vector<const ServerPin*>& out) const;
			int					_ZoomToTileZoom() const;

			OwningObjectList<ServerPin>	fPins;

			bool				fHasSelfPosition;
			float				fSelfLat;
			float				fSelfLon;
			BString				fSelfLabel;
			BString				fActiveHost;

			float				fCenterLat;
			float				fCenterLon;
			float				fZoom;		// pixels per degree longitude

			bool				fDragging;
			bool				fDragMoved;
			BPoint				fDragStart;
			float				fDragStartLat;
			float				fDragStartLon;

			ServerPin*			fSelectedPin;
			ServerPin*			fHoverPin;

			TileCache*			fTileCache;
			bool				fShowTiles;
			bool				fShowCoastlines;

			int					fLastTileZ;
			int					fLastTileMinX;
			int					fLastTileMinY;
			int					fLastTileMaxX;
			int					fLastTileMaxY;
};


#endif	// MAP_VIEW_H
