"""Cloudflare's own numbers for the domains an account holds.

Two APIs, both under `api.cloudflare.com/client/v4` and both taking the same token:

    /zones           the domains, over REST. This is where the names come from, and it is
                     the only place they exist: the analytics API knows a zone by its tag.
    /graphql         the readings. Zone Analytics' own REST endpoint refuses an
                     account-owned token and says so, naming GraphQL as the replacement.

Each domain becomes a group in the frame - `cf_pinout_xyz.requests` - so the built-in page
kinds draw it with no badge-side code, and a `cloudflare` group carries the account's
totals for a page that wants one number. Nothing here draws, so there is no badge module.

The live figures come from `httpRequestsAdaptiveGroups`, which reports by the minute and is
current to about a minute; its `count` is already corrected for sampling, and is within a
percent of the hourly dataset's own total for the same hour. The daily figures come from
`httpRequests1dGroups`, which is today so far in UTC and not a rolling day.
"""

import datetime
import json
import re
import threading
import time
import urllib.error
import urllib.request

from statsbadge.sources.base import Source

API = "https://api.cloudflare.com/client/v4"

# How often the readings are asked for. Not a setting: the live window is a minute's
# resolution, so asking faster returns the same figures, and asking slower only makes them
# older - one query a minute against a limit of 300 in five is not a budget worth managing.
EVERY = 60.0
# The domain list changes when somebody adds a site, which is not something to poll for.
ZONES_EVERY = 3600.0
# A failure waits this long rather than the whole interval, and rather than never.
RETRY_AFTER = 60.0
FETCH_POLL = 1.0

# What "now" covers. The most recent minute is still being written, so the window ends a
# minute back; five of them is enough that a quiet site reads as a rate rather than as a
# row of noughts.
LIVE_MINUTES = 5
LIVE_LAG_MINUTES = 1

# What this says when it has not been given a token. Not counted as a fault - an extension
# nobody has configured is not broken - but worth showing, since a silent source reporting
# nothing looks the same as one that is not installed.
UNSET = "no API token set"

# Where the domain list is kept between runs, so the checkboxes are there before the first
# fetch lands and a save made while the network is down keeps the ones already ticked.
ZONES = "zones"

# How many domains are watched without anybody saying so. An account is added here to see
# what is on it, and a first run showing nothing would look broken - but a domain is 560
# bytes in the frame the badge fetches every second, against 832 for the whole of what a
# host reports about itself, so an account with forty of them starts them all off instead.
DEFAULT_ON_LIMIT = 8

# A request a second is a busy site, and it is the floor the peak decays to: without one a
# domain that goes quiet overnight would have every gauge pegged by breakfast.
REQUESTS_FLOOR = 60.0
BYTES_FLOOR = 4096.0

# Requests are counted by the minute here and shown as a rate, so they get the unit a rate
# has. Fields are named the same in every group on purpose: the host keys units and scales
# by the field name, so one name means one unit whichever domain it is read from.
FIELDS = {
    # `history` rather than `graphed`: the collector would sample these at its own rate, and
    # ninety samples of a reading fetched once a minute is a minute and a half of staircase.
    # Cloudflare reports by the hour, so `series()` hands over a day of them instead.
    "requests": {"label": "Requests / min", "unit": "/min", "history": True,
                 "peak": True, "peak_floor": REQUESTS_FLOOR},
    "bytes_bps": {"label": "Served", "unit": "B/s", "history": True,
                  "peak": True, "peak_floor": BYTES_FLOOR},
    "cached_pct": {"label": "Cached %", "unit": "%", "percent": True, "history": True},
    "requests_today": {"label": "Requests today"},
    "pageviews_today": {"label": "Page views today"},
    "uniques_today": {"label": "Unique visitors today"},
    "threats_today": {"label": "Threats today"},
    "bytes_today_mb": {"label": "Served today", "unit": "MB"},
}

# The totals across every domain being watched. Unique visitors are left out: a visitor to
# two sites is two of them, so the sum is not a count of anybody.
TOTAL_FIELDS = {name: entry for name, entry in FIELDS.items() if name != "uniques_today"}
TOTALS = "cloudflare"

# A day of hourly buckets, which is what a graph of this is worth drawing from. The newest
# is the hour in progress and is dropped: a bucket a few minutes into its hour reads as
# traffic falling off a cliff, which is the shape of a partial count and not of a day.
HOURS = 24
HOUR_MS = 3600 * 1000

# One selection per domain, aliased so the tag never has to be written into the query.
QUERY_HEAD = "query({args}) {{\n  viewer {{\n"
QUERY_ZONE = """    {alias}: zones(filter: {{zoneTag: ${alias}}}) {{
      live: httpRequestsAdaptiveGroups(
          limit: 1, filter: {{datetime_geq: $from, datetime_lt: $to}}) {{
        count
        sum {{ edgeResponseBytes }}
      }}
      today: httpRequests1dGroups(limit: 1, filter: {{date_geq: $today}}) {{
        sum {{ requests bytes cachedRequests threats pageViews }}
        uniq {{ uniques }}
      }}
      hourly: httpRequests1hGroups(
          limit: {hours}, filter: {{datetime_geq: $hour_from, datetime_lt: $hour_to}},
          orderBy: [datetime_ASC]) {{
        dimensions {{ datetime }}
        sum {{ requests bytes cachedRequests }}
      }}
    }}
"""
QUERY_TAIL = "  }\n}\n"


class Cloudflare(Source):
    name = "cloudflare"
    label = "Cloudflare"

    settings = (
        {"key": "api_token", "label": "API token", "type": "text", "secret": True,
         "hint": "A token with Zone / Zone / Read to list the domains and "
                 "Zone / Analytics / Read for their traffic. Made at "
                 "dash.cloudflare.com/profile/api-tokens"},
    )

    every = EVERY

    @classmethod
    def available(cls):
        return True

    def __init__(self, config):
        super().__init__(config)
        # The domains, and what was last read for each, keyed by group name. Both are
        # replaced on the fetcher's thread and read while sampling, so both go through
        # the lock.
        self._zones = []
        self._readings = {}
        # A day of hourly points per group, and the hour they run up to. What a graph of
        # any of this is drawn from: the readings above are one moment, these are the shape.
        self._hourly = {}
        self._hourly_to = None
        self._lock = threading.Lock()
        self._next = 0.0
        self._next_zones = 0.0
        self._fetcher = None
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._read_settings()

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        """Take up the domain list the last run found, then fetch on a thread of its own.

        Nothing in `sample` may wait on a network: every source shares the collector's
        thread and the first sample is taken while the server is still starting up.
        """
        with self._lock:
            self._zones = [dict(zone) for zone in (self.store.get(ZONES) or ())]
        self._read_settings()
        if self._fetcher is None:
            self._stop.clear()
            self._fetcher = threading.Thread(target=self._fetch_loop, daemon=True,
                                             name="statsbadge-cloudflare")
            self._fetcher.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._fetcher is not None:
            self._fetcher.join(timeout=2.0)
            self._fetcher = None

    def configure(self, settings):
        """Take settings while running, and ask again rather than waiting out the interval.

        A token pasted into the browser should turn up as a list of domains, and a domain
        ticked should turn up as a group, without anybody restarting the server.
        """
        super().configure(settings)
        self._read_settings()
        if self.last_fault == UNSET and self.token:
            # That message was about the setting, and it has just been given. Waiting for a
            # fetch to succeed before withdrawing it leaves the config page saying a token
            # is missing for as long as the first request takes.
            self.last_fault = None
        self._next = 0.0
        self._next_zones = 0.0
        self._wake.set()

    # -- what this source offers --------------------------------------------

    def _read_settings(self):
        """Re-read the settings, and rebuild what is offered from the domains now known.

        `settings` and `groups` are read off the source rather than off the class, so the
        checkbox for a domain and the group it fills both appear as soon as the account
        has been asked what it holds.
        """
        self.token = str(self.config.get("api_token") or "").strip()

        with self._lock:
            zones = list(self._zones)
        watch_by_default = len(zones) <= DEFAULT_ON_LIMIT
        self._watched = [zone for zone in zones
                         if self.config.get(f"zone_{zone['slug']}", watch_by_default)]

        self.settings = tuple(Cloudflare.settings) + tuple(
            {"key": f"zone_{zone['slug']}", "label": zone["name"], "type": "bool",
             "default": watch_by_default}
            for zone in zones)
        # Slow, every one of them: the readings are fetched once a minute and the badge
        # polls once a second, so they travel when they change and not sixty times over.
        groups = {f"cf_{zone['slug']}": {"label": zone["name"], "slow": True,
                                         "fields": dict(FIELDS)}
                  for zone in self._watched}
        if self._watched:
            # Named for what it is rather than for the account, the picker heading it
            # sits under already being Cloudflare's.
            groups[TOTALS] = {"label": "All domains", "slow": True,
                              "fields": {**TOTAL_FIELDS,
                                         "zones": {"label": "Domains watched"}}}
        self.groups = groups
        self.provides = tuple(groups)

    # -- sampling -----------------------------------------------------------

    def sample(self, frame, dt):
        """Whatever the fetcher last brought back. Nothing here touches the network."""
        with self._lock:
            readings = {group: dict(values) for group, values in self._readings.items()
                        # A domain unticked a moment ago is still in the last answer, and
                        # a group nothing declares is a group nothing can draw.
                        if group in self.groups}
        for group, values in readings.items():
            frame[group] = values
        if readings:
            frame[TOTALS] = _totals(readings)

    def series(self):
        """A day of hourly points per watched domain, and the same summed across them.

        The collector would otherwise sample these at its own rate, and ninety samples of a
        reading fetched once a minute is a minute and a half of staircase. Cloudflare reports
        by the hour, so this is a day of real shape instead - and it says so, since a plot
        walked by a number counted in the host's own samples would slide a year an hour.
        """
        with self._lock:
            hourly = {group: dict(hours) for group, hours in self._hourly.items()
                      if group in self.groups}
            hour_to = self._hourly_to
        if not hourly or hour_to is None:
            return {}
        age_ms = max(0, int((datetime.datetime.now(datetime.timezone.utc)
                             - hour_to).total_seconds() * 1000))
        out = {}
        for group, fields in hourly.items():
            for field, points in fields.items():
                out[f"{group}.{field}"] = {"points": points, "every_ms": HOUR_MS,
                                           "age_ms": age_ms}
        totals = _total_hours(hourly)
        for field, points in totals.items():
            out[f"{TOTALS}.{field}"] = {"points": points, "every_ms": HOUR_MS,
                                        "age_ms": age_ms}
        return out

    def note_fault(self, exc):
        """What Cloudflare said, without a type name in front of it.

        `readable` names the type of anything it does not recognise, which is right for a
        fault nobody expected and wrong for a message written to be read: the alternative
        here is "CloudflareError: HTTP 403: ...", which says it twice.
        """
        if isinstance(exc, CloudflareError):
            self.faults += 1
            self.last_fault = str(exc)
            return
        super().note_fault(exc)

    # -- fetching -----------------------------------------------------------

    def _fetch_loop(self):
        while not self._stop.is_set():
            try:
                self._refresh()
            except Exception as exc:
                # The fetcher must not die, or the readings would stand at whatever they
                # last were with nothing ever replacing them.
                self.note_fault(exc)
            self._wake.wait(FETCH_POLL)
            self._wake.clear()

    def _refresh(self):
        if not self.token:
            # Not a fault: an extension nobody has given a token to is unconfigured, and
            # counting that would report a broken source on every host that installed it.
            # The line is still worth showing, since the alternative is a silent source.
            self.last_fault = UNSET
            return
        now = time.monotonic()
        if now >= self._next_zones:
            try:
                self._refresh_zones()
            except Exception as exc:
                self._next_zones = now + RETRY_AFTER
                self.note_fault(exc)
                return
            self._next_zones = time.monotonic() + ZONES_EVERY
        if now < self._next:
            return
        try:
            readings = self._fetch_readings()
        except Exception as exc:
            self._next = time.monotonic() + RETRY_AFTER
            self.note_fault(exc)
            return
        with self._lock:
            self._readings = readings
        self._next = time.monotonic() + self.every
        self.note_ok()

    def _refresh_zones(self):
        """The domains on the account, by name. Kept, so the next run starts with them."""
        zones = []
        page = 1
        while True:
            body = self._rest(f"/zones?per_page=50&page={page}")
            for record in body.get("result") or ():
                name = str(record.get("name") or "")
                if record.get("id") and name:
                    zones.append({"id": record["id"], "name": name,
                                  "slug": _slug(name)})
            info = body.get("result_info") or {}
            if page >= int(info.get("total_pages") or 1):
                break
            page += 1
        with self._lock:
            known = self._zones
            self._zones = zones
        if zones != known:
            self.store.set(ZONES, zones)
            # A domain added to the account is a checkbox and a group that were not there
            # a moment ago, so what this source offers is rebuilt rather than left until
            # somebody saves the settings again.
            self._read_settings()

    def _fetch_readings(self):
        watched = list(self._watched)
        if not watched:
            return {}
        end = (datetime.datetime.now(datetime.timezone.utc)
               .replace(second=0, microsecond=0)
               - datetime.timedelta(minutes=LIVE_LAG_MINUTES))
        start = end - datetime.timedelta(minutes=LIVE_MINUTES)
        # Whole hours only, ending at the last one that finished.
        hour_to = end.replace(minute=0)
        hour_from = hour_to - datetime.timedelta(hours=HOURS)
        variables = {"from": _stamp(start), "to": _stamp(end),
                     "today": end.strftime("%Y-%m-%d"),
                     "hour_from": _stamp(hour_from), "hour_to": _stamp(hour_to)}
        aliases = []
        for index, zone in enumerate(watched):
            alias = f"z{index}"
            aliases.append(alias)
            variables[alias] = zone["id"]

        declared = ", ".join(["$from: Time!", "$to: Time!", "$today: Date!",
                              "$hour_from: Time!", "$hour_to: Time!"]
                             + [f"${alias}: String!" for alias in aliases])
        query = (QUERY_HEAD.format(args=declared)
                 + "".join(QUERY_ZONE.format(alias=alias, hours=HOURS)
                           for alias in aliases)
                 + QUERY_TAIL)
        answer = self._graphql(query, variables)

        viewer = (answer.get("data") or {}).get("viewer") or {}
        readings, hourly = {}, {}
        for alias, zone in zip(aliases, watched, strict=True):
            found = viewer.get(alias) or ()
            if found:
                readings[f"cf_{zone['slug']}"] = _zone_reading(found[0])
                hourly[f"cf_{zone['slug']}"] = _zone_hours(found[0], hour_from)
        with self._lock:
            self._hourly = hourly
            self._hourly_to = hour_to
        # Partial answers are the normal shape of a failure here: a dataset one plan has
        # and another does not comes back as an error beside the zones that did answer, so
        # what did arrive is kept and the reason is reported.
        if answer.get("errors"):
            raise CloudflareError(_first_error(answer["errors"]))
        return readings

    # -- talking to it ------------------------------------------------------

    def _rest(self, path):
        body = self._request(API + path)
        if not body.get("success", True):
            raise CloudflareError(_first_error(body.get("errors")))
        return body

    def _graphql(self, query, variables):
        payload = json.dumps({"query": query, "variables": variables}).encode("utf-8")
        return self._request(f"{API}/graphql", payload)

    def _request(self, url, payload=None):
        request = urllib.request.Request(url, data=payload, headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # The status alone says nothing useful: a token missing one permission is a
            # 403 whose body names the permission.
            detail = _first_error(_errors_in(exc.read()))
            if not detail:
                raise
            raise CloudflareError(f"HTTP {exc.code}: {detail}") from exc


class CloudflareError(Exception):
    """What Cloudflare said was wrong, as one line for the config UI to show."""


def _zone_reading(found):
    """One zone's two selections as the fields a page can draw."""
    live = (found.get("live") or [{}])[0] or {}
    today = (found.get("today") or [{}])[0] or {}
    sums = today.get("sum") or {}
    requests_today = sums.get("requests")
    cached = sums.get("cachedRequests")
    bytes_today = sums.get("bytes")
    return {
        "requests": round((live.get("count") or 0) / float(LIVE_MINUTES), 1),
        "bytes_bps": round(((live.get("sum") or {}).get("edgeResponseBytes") or 0)
                           / (LIVE_MINUTES * 60.0)),
        "cached_pct": (round(100.0 * cached / requests_today, 1)
                       if requests_today and cached is not None else None),
        "requests_today": requests_today,
        "pageviews_today": sums.get("pageViews"),
        "uniques_today": (today.get("uniq") or {}).get("uniques"),
        "threats_today": sums.get("threats"),
        "bytes_today_mb": (round(bytes_today / (1024.0 * 1024.0), 1)
                           if bytes_today is not None else None),
    }


def _zone_hours(found, hour_from):
    """One zone's hourly buckets as the three fields a plot can draw, oldest first.

    Placed by their timestamps rather than taken in the order they arrived: an hour with no
    traffic at all is a bucket the API leaves out, and packing what is left would draw a
    quiet night as though it had never happened. A missing hour is None, which is what a
    plot needs to draw a gap where there was no reading.
    """
    by_hour = {}
    for row in found.get("hourly") or ():
        stamp = (row.get("dimensions") or {}).get("datetime")
        if not stamp:
            continue
        try:
            when = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        index = int((when - hour_from).total_seconds() // 3600)
        if 0 <= index < HOURS:
            by_hour[index] = row.get("sum") or {}

    requests, served, cached = [], [], []
    for index in range(HOURS):
        sums = by_hour.get(index)
        if sums is None:
            requests.append(None)
            served.append(None)
            cached.append(None)
            continue
        count = sums.get("requests")
        hit = sums.get("cachedRequests")
        # Per minute and per second, the same units the live readings are in: one field
        # means one unit whether it is being read now or plotted from an hour ago.
        requests.append(None if count is None else round(count / 60.0, 1))
        served.append(None if sums.get("bytes") is None
                      else round(sums["bytes"] / 3600.0))
        cached.append(round(100.0 * hit / count, 1)
                      if count and hit is not None else None)
    return {"requests": requests, "bytes_bps": served, "cached_pct": cached}


def _total_hours(hourly):
    """The same three, added across every watched domain, hour by hour."""
    totals = {}
    for field in ("requests", "bytes_bps"):
        added = []
        for index in range(HOURS):
            known = [fields[field][index] for fields in hourly.values()
                     if fields.get(field) and fields[field][index] is not None]
            added.append(round(sum(known), 1) if known else None)
        totals[field] = added
    # A percentage of percentages is not a sum, so the hit rate comes back off the requests
    # behind it, the same way the live one does.
    rate = []
    for index in range(HOURS):
        served = sum((fields["requests"][index] or 0)
                     for fields in hourly.values() if fields.get("requests"))
        hit = sum((fields["requests"][index] or 0) * (fields["cached_pct"][index] or 0)
                  / 100.0
                  for fields in hourly.values() if fields.get("cached_pct"))
        rate.append(round(100.0 * hit / served, 1) if served else None)
    totals["cached_pct"] = rate
    return totals


def _totals(readings):
    """Every watched domain added up, for a page wanting one number for the account.

    A field nothing answered stays None rather than becoming zero: the badge draws "--"
    for the first and a reading for the second.
    """
    total = {"zones": len(readings)}
    for field in TOTAL_FIELDS:
        values = [values.get(field) for values in readings.values()]
        known = [value for value in values if value is not None]
        total[field] = round(sum(known), 1) if known else None
    # A rate of rates is a sum; a percentage of percentages is not, so the cache hit rate
    # is worked out again from the requests behind it.
    served = sum(values.get("requests_today") or 0 for values in readings.values())
    cached = sum((values.get("requests_today") or 0)
                 * (values.get("cached_pct") or 0) / 100.0
                 for values in readings.values())
    total["cached_pct"] = round(100.0 * cached / served, 1) if served else None
    return total


def _slug(name):
    """A domain as a group name: "pinout.xyz" is `cf_pinout_xyz`.

    A field reference is "group.field" split on its one dot, so a group carrying a domain
    name cannot keep the dots in it.
    """
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "zone"


def _stamp(when):
    return when.strftime("%Y-%m-%dT%H:%M:00Z")


def _errors_in(body):
    try:
        return (json.loads(body.decode("utf-8")) or {}).get("errors")
    except Exception:
        return None


def _first_error(errors):
    """The first thing Cloudflare complained about, as a line.

    Both APIs answer with a list, and the first is the one worth showing: the rest
    are usually the same complaint about the next zone along.
    """
    for error in errors or ():
        message = (error or {}).get("message")
        if message:
            return str(message)
    return "the request was refused, with no reason given"
