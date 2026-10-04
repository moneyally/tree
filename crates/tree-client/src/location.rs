//! Location and live location (`chat.location`, APP_PROTOCOL.md 8.3).
//!
//! A place is latitude, longitude (integers in 10^-7 degrees), accuracy and
//! an optional label, sent inside MLS like a text; the server never sees
//! it. A live location is a place with a duration (15 minutes, 1 hour or
//! 8 hours): the app hands the client new coordinates whenever it has
//! them; the client sends at most one update every 30 seconds (newer
//! coordinates replace waiting ones and go out with a later sync) and
//! stops when the time is up or the user stops it. Every receiver measures
//! the duration with its own clock from when the start arrived; updates
//! after that, or from anyone but the sender, are dropped, and an expired
//! live location shows as ended.
//!
//! Map tiles: apps may draw a map through the server's tile relay
//! ([`Session::map_tile`], `server.map_relay`); without one they show the
//! coordinates and an "open in maps app" action.

use serde::{Deserialize, Serialize};
use tree_core::MemberId;

use crate::messages::now;
use crate::payload::{LocationInfo, Payload};
use crate::{Error, Event, Session};

/// Live location durations the apps offer (seconds).
pub const LIVE_CHOICES: [u32; 3] = [900, 3600, 8 * 3600];
/// Longest live location a receiver accepts.
pub const MAX_LIVE_SECS: u32 = 8 * 3600;
/// At most one live update this often (seconds).
pub const LIVE_MIN_INTERVAL: i64 = 30;
/// Label length (characters).
pub const MAX_LABEL: usize = 200;
/// Largest accuracy radius taken (metres).
pub const MAX_ACCURACY: u32 = 100_000;
const INTERVAL_KEY: &str = "location/min_interval";

/// What a stored location message keeps (its `data`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    lat_e7: i64,
    lon_e7: i64,
    #[serde(default)]
    accuracy_m: Option<u32>,
    #[serde(default)]
    label: Option<String>,
    /// End of a live location by this device's clock.
    #[serde(default)]
    live_until: Option<i64>,
    #[serde(default)]
    stopped: bool,
    updated_at: i64,
}

/// A live location this device is sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LiveOut {
    until: i64,
    last_sent: i64,
    /// Coordinates waiting for the 30 s interval.
    #[serde(default)]
    pending: Option<(i64, i64, Option<u32>)>,
}

/// A location message as the apps show it.
#[derive(Debug, Clone, PartialEq)]
pub struct LocationView {
    pub id: String,
    pub sender: String,
    pub lat: f64,
    pub lon: f64,
    pub accuracy_m: Option<u32>,
    pub label: Option<String>,
    /// Still live now (updates may come).
    pub live: bool,
    /// When a live location ends (this device's clock).
    pub live_until: Option<i64>,
    /// Was live and is over (stopped or expired): the last position stays.
    pub ended: bool,
    /// When the position last changed (this device's clock).
    pub updated_at: i64,
}

fn e7(deg: f64, max: f64) -> Result<i64, Error> {
    if !deg.is_finite() || deg.abs() > max {
        return Err(Error::Usage("coordinates out of range".into()));
    }
    Ok((deg * 1e7).round() as i64)
}

fn coords_ok(lat_e7: i64, lon_e7: i64, acc: Option<u32>) -> bool {
    lat_e7.abs() <= 900_000_000 && lon_e7.abs() <= 1_800_000_000 && acc.is_none_or(|a| a <= MAX_ACCURACY)
}

fn live_key(gid: &[u8], id: &str) -> String {
    format!("liveout/{}/{id}", hex::encode(gid))
}

/// A `geo:` link for "open in maps app".
pub fn geo_uri(lat: f64, lon: f64, label: Option<&str>) -> String {
    let base = format!("geo:{lat:.7},{lon:.7}");
    match label {
        Some(l) if !l.is_empty() => {
            let enc: String = l
                .bytes()
                .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
                .collect();
            format!("{base}?q={lat:.7},{lon:.7}({enc})")
        }
        _ => base,
    }
}

impl Session {
    fn location_allowed(&mut self, gid: &[u8]) -> Result<(), Error> {
        if !self.chat_feature(gid, "chat.location")?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        Ok(())
    }

    fn send_place(&mut self, gid: &[u8], lat: f64, lon: f64, accuracy_m: Option<u32>, label: Option<&str>, live: Option<u32>) -> Result<String, Error> {
        self.location_allowed(gid)?;
        let (lat_e7, lon_e7) = (e7(lat, 90.0)?, e7(lon, 180.0)?);
        if accuracy_m.is_some_and(|a| a > MAX_ACCURACY) || label.is_some_and(|l| l.chars().count() > MAX_LABEL) {
            return Err(Error::Usage("accuracy or label too large".into()));
        }
        let id = crate::messages::new_id();
        let label = label.map(str::trim).filter(|l| !l.is_empty()).map(str::to_string);
        let t = now();
        let stored = Stored { lat_e7, lon_e7, accuracy_m, label: label.clone(), live_until: live.map(|s| t + s as i64), stopped: false, updated_at: t };
        let data = serde_json::to_vec(&stored).expect("JSON");
        let me = self.member_id();
        let p = Payload::Location(LocationInfo { id: id.clone(), lat_e7, lon_e7, accuracy_m, label: label.clone(), live_secs: live });
        self.queue_payload(gid, &p, Some(&id), |s| s.store(gid, &id, &me, "location", label, Some(data), None).map(|_| ()))?;
        if let Some(secs) = live {
            self.app_put(&live_key(gid, &id), Some(&LiveOut { until: t + secs as i64, last_sent: t, pending: None }))?;
        }
        Ok(id)
    }

    /// Sends a place (`chat.location`); returns the message id.
    pub fn send_location(&mut self, gid: &[u8], lat: f64, lon: f64, accuracy_m: Option<u32>, label: Option<&str>) -> Result<String, Error> {
        self.send_place(gid, lat, lon, accuracy_m, label, None)
    }

    /// Starts sharing a live location for `seconds` (one of
    /// [`LIVE_CHOICES`]); returns its id for updates.
    pub fn start_live_location(&mut self, gid: &[u8], lat: f64, lon: f64, accuracy_m: Option<u32>, seconds: u32) -> Result<String, Error> {
        if !LIVE_CHOICES.contains(&seconds) {
            return Err(Error::Usage("a live location lasts 15 minutes, 1 hour or 8 hours".into()));
        }
        self.send_place(gid, lat, lon, accuracy_m, None, Some(seconds))
    }

    fn live_interval(&self) -> Result<i64, Error> {
        Ok(self.app_get::<i64>(INTERVAL_KEY)?.unwrap_or(LIVE_MIN_INTERVAL))
    }

    /// Shortens the 30-second update interval. Only for tests.
    #[doc(hidden)]
    pub fn set_live_interval_for_tests(&self, secs: i64) -> Result<(), Error> {
        self.app_put(INTERVAL_KEY, Some(&secs.max(0)))
    }

    /// New coordinates for a live location this device is sharing. Sent
    /// now if the last update is at least 30 seconds old (returns true);
    /// otherwise kept and sent by a later sync (false). Fails once the live
    /// location ended.
    pub fn update_live_location(&mut self, gid: &[u8], id: &str, lat: f64, lon: f64, accuracy_m: Option<u32>) -> Result<bool, Error> {
        let mut out: LiveOut = self.app_get(&live_key(gid, id))?.ok_or_else(|| Error::Usage("this live location has ended".into()))?;
        let t = now();
        if !self.chat_feature(gid, "chat.location")?.0 {
            self.app_put::<LiveOut>(&live_key(gid, id), None)?;
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        if t >= out.until {
            self.app_put::<LiveOut>(&live_key(gid, id), None)?;
            return Err(Error::Usage("this live location has ended".into()));
        }
        let c = (e7(lat, 90.0)?, e7(lon, 180.0)?, accuracy_m.filter(|a| *a <= MAX_ACCURACY));
        if t - out.last_sent < self.live_interval()? {
            out.pending = Some(c);
            self.app_put(&live_key(gid, id), Some(&out))?;
            return Ok(false);
        }
        self.send_live(gid, id, c, false)?;
        out.last_sent = t;
        out.pending = None;
        self.app_put(&live_key(gid, id), Some(&out))?;
        Ok(true)
    }

    /// Stops sharing a live location now; the last position stays.
    pub fn stop_live_location(&mut self, gid: &[u8], id: &str) -> Result<(), Error> {
        let out: LiveOut = self.app_get(&live_key(gid, id))?.ok_or_else(|| Error::Usage("this live location has ended".into()))?;
        self.app_put::<LiveOut>(&live_key(gid, id), None)?;
        let c = out.pending.unwrap_or_else(|| self.own_coords(gid, id).unwrap_or((0, 0, None)));
        self.send_live(gid, id, c, true)
    }

    fn own_coords(&self, gid: &[u8], id: &str) -> Option<(i64, i64, Option<u32>)> {
        let m = self.client.message(gid, id).ok()??;
        let s: Stored = serde_json::from_slice(m.data.as_deref()?).ok()?;
        Some((s.lat_e7, s.lon_e7, s.accuracy_m))
    }

    fn send_live(&mut self, gid: &[u8], id: &str, (lat_e7, lon_e7, accuracy_m): (i64, i64, Option<u32>), stop: bool) -> Result<(), Error> {
        let p = Payload::LiveLocation { id: id.to_string(), lat_e7, lon_e7, accuracy_m, stop };
        self.queue_payload(gid, &p, None, |s| s.move_location(gid, id, (lat_e7, lon_e7, accuracy_m), stop))?;
        Ok(())
    }

    /// Updates the stored position of location `id`.
    fn move_location(&self, gid: &[u8], id: &str, (lat_e7, lon_e7, accuracy_m): (i64, i64, Option<u32>), stop: bool) -> Result<(), Error> {
        let Some(m) = self.client.message(gid, id)? else { return Ok(()) };
        let Some(mut s) = m.data.as_deref().and_then(|d| serde_json::from_slice::<Stored>(d).ok()) else { return Ok(()) };
        s.lat_e7 = lat_e7;
        s.lon_e7 = lon_e7;
        s.accuracy_m = accuracy_m;
        s.stopped |= stop;
        s.updated_at = now();
        Ok(self.client.set_message_data(gid, id, Some(&serde_json::to_vec(&s).expect("JSON")))?)
    }

    /// Sends waiting live updates that are due and forgets live locations
    /// that ended (every sync).
    pub(crate) fn flush_live_locations(&mut self) -> Result<(), Error> {
        let t = now();
        let interval = self.live_interval()?;
        for k in self.client.app_data_keys("liveout/")? {
            let Some(mut out) = self.app_get::<LiveOut>(&k)? else { continue };
            let mut parts = k["liveout/".len()..].splitn(2, '/');
            let (Some(g), Some(id)) = (parts.next(), parts.next()) else { continue };
            let Ok(gid) = hex::decode(g) else { continue };
            // Ended, gone, or the chat released locations: stop sharing.
            if t >= out.until || !self.client.group_ids()?.contains(&gid) || !self.chat_feature(&gid, "chat.location")?.0 {
                self.app_put::<LiveOut>(&k, None)?;
                continue;
            }
            if let Some(c) = out.pending.filter(|_| t - out.last_sent >= interval) {
                let id = id.to_string();
                let _ = self.send_live(&gid, &id, c, false);
                out.last_sent = t;
                out.pending = None;
                self.app_put(&k, Some(&out))?;
            }
        }
        Ok(())
    }

    /// A location message of the group as the apps show it now.
    pub fn location(&self, gid: &[u8], id: &str) -> Result<Option<LocationView>, Error> {
        let Some(m) = self.client.message(gid, id)? else { return Ok(None) };
        if m.kind != "location" || m.deleted {
            return Ok(None);
        }
        let Some(s) = m.data.as_deref().and_then(|d| serde_json::from_slice::<Stored>(d).ok()) else { return Ok(None) };
        let t = now();
        let live = s.live_until.is_some_and(|u| t < u) && !s.stopped;
        Ok(Some(LocationView {
            id: m.id,
            sender: m.sender,
            lat: s.lat_e7 as f64 / 1e7,
            lon: s.lon_e7 as f64 / 1e7,
            accuracy_m: s.accuracy_m,
            label: s.label,
            live,
            live_until: s.live_until,
            ended: s.live_until.is_some() && !live,
            updated_at: s.updated_at,
        }))
    }

    pub(crate) fn on_location(&mut self, gid: &[u8], from: MemberId, l: LocationInfo, franking: Option<Vec<u8>>, events: &mut Vec<Event>) -> Result<(), Error> {
        if !self.chat_feature(gid, "chat.location")?.0 {
            events.push(Event::Dropped { reason: "locations are released in this group (chat.location)".into() });
            return Ok(());
        }
        let label_ok = l.label.as_ref().is_none_or(|x| x.chars().count() <= MAX_LABEL);
        let live_ok = l.live_secs.is_none_or(|s| (1..=MAX_LIVE_SECS).contains(&s));
        if l.id.is_empty() || l.id.len() > crate::rich::MAX_ID || !coords_ok(l.lat_e7, l.lon_e7, l.accuracy_m) || !label_ok || !live_ok {
            events.push(Event::Dropped { reason: "malformed location".into() });
            return Ok(());
        }
        let t = now();
        let s = Stored {
            lat_e7: l.lat_e7,
            lon_e7: l.lon_e7,
            accuracy_m: l.accuracy_m,
            label: l.label.clone(),
            live_until: l.live_secs.map(|x| t + x as i64),
            stopped: false,
            updated_at: t,
        };
        if !self.store(gid, &l.id, &from, "location", l.label, Some(serde_json::to_vec(&s).expect("JSON")), franking)? {
            events.push(Event::Dropped { reason: "duplicate message id".into() });
            return Ok(());
        }
        self.on_new_message(gid, false)?;
        let name = self.names(gid)?.get(&from.to_hex()).cloned();
        let request = self.is_request(gid)?;
        events.push(Event::Location { group: gid.to_vec(), id: l.id, from, name, live: l.live_secs.is_some(), request });
        Ok(())
    }

    pub(crate) fn on_live_location(
        &mut self,
        gid: &[u8],
        from: MemberId,
        id: &str,
        c: (i64, i64, Option<u32>),
        stop: bool,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if !self.chat_feature(gid, "chat.location")?.0 {
            events.push(Event::Dropped { reason: "locations are released in this group (chat.location)".into() });
            return Ok(());
        }
        let Some(view) = self.location(gid, id)? else {
            events.push(Event::Dropped { reason: "update of an unknown location".into() });
            return Ok(());
        };
        if view.sender != from.to_hex() || !view.live || !coords_ok(c.0, c.1, c.2) {
            events.push(Event::Dropped { reason: "live location update refused (not the sender's, ended, or malformed)".into() });
            return Ok(());
        }
        self.move_location(gid, id, c, stop)?;
        events.push(Event::LocationUpdated { group: gid.to_vec(), id: id.to_string(), from, stopped: stop });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinates_and_links() {
        assert_eq!(e7(37.5665, 90.0).unwrap(), 375_665_000);
        assert_eq!(e7(-180.0, 180.0).unwrap(), -1_800_000_000);
        assert!(e7(90.1, 90.0).is_err() && e7(f64::NAN, 90.0).is_err());
        assert!(coords_ok(900_000_000, -1_800_000_000, Some(10)));
        assert!(!coords_ok(900_000_001, 0, None) && !coords_ok(0, 0, Some(MAX_ACCURACY + 1)));
        assert_eq!(geo_uri(37.5, 127.0, None), "geo:37.5000000,127.0000000");
        assert_eq!(geo_uri(1.0, 2.0, Some("a b")), "geo:1.0000000,2.0000000?q=1.0000000,2.0000000(a%20b)");
        assert_eq!(LIVE_CHOICES, [900, 3600, 28_800]);
    }
}
