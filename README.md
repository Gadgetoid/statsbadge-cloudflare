# statsbadge-cloudflare

Your Cloudflare traffic as readings, for [statsbadge](https://github.com/pimoroni/statsbadge).

Every domain on your account becomes a source you can point a page at: requests a minute, bytes a second, cache hit rate, and the day's totals. There is a **Cloudflare, all domains** source too, for a page that wants one number for everything.

## Install

```bash
statsbadge ext add cloudflare
```

Then, in the config UI under **Extensions**, paste an API token. The domains appear as checkboxes on the next reload, and each one that is ticked becomes a source in the field pickers.

Up to eight domains are ticked by default, keeping the payload small.

## The token

Make one at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with two permissions:

| Permission | What it is for |
| ---------- | -------------- |
| Zone / Zone / Read | listing the domains. It is the only place their names exist |
| Zone / Analytics / Read | the traffic |

Include every zone you want to see. The token is stored in the host's config file in plain text.

## Settings

| Setting | What it does |
| ------- | ------------ |
| API token | The token above |
| One per domain | Whether to watch it. Untick what you are not going to draw |

## What each domain reports

| Reading | What it is |
| ------- | ---------- |
| Requests / min | Averaged over the last five minutes |
| Served | Bytes a second over the same five minutes |
| Cached % | Of today's requests, how many the edge answered |
| Requests today | Today so far, in UTC |
| Page views today | |
| Unique visitors today | |
| Threats today | What Cloudflare blocked or challenged |
| Served today | |

The totals source has all of these bar unique visitors, plus how many domains are being watched. A visitor to two of your sites is two uniques, so summing them counts nobody in particular.

Requests, bytes and the cache hit rate are graphable, and the history is Cloudflare's: **a day of hourly points**, so a graph shows the shape of a day rather than the last ninety seconds. It is there the moment you add the page, and requests and bytes are scaled vertically to fill up the graph.

## Notes

The names come from the REST API and the numbers from GraphQL, both under `api.cloudflare.com/client/v4` and both on the same token. Zone Analytics' own REST endpoint refuses an account-owned token outright and names GraphQL as its replacement, so that is the one used.

Live figures come from `httpRequestsAdaptiveGroups`, which reports by the minute and is current to about a minute. Its count is already corrected for sampling: measured against the hourly dataset over the same hour, the two agree to within a percent. The window ends a minute back, because the newest minute is still being written.

The daily figures are today so far in UTC, not a rolling twenty-four hours, which is what Cloudflare's own dashboard shows for the day.

The graph's points are hourly buckets, oldest to newest, with the hour in progress left off: a bucket a few minutes into its hour reads as traffic falling off a cliff, which is the shape of a partial count and not of a day. An hour with no traffic at all is a bucket Cloudflare leaves out, and it is drawn as a gap rather than closed up.

Requests are per minute and bytes per second whether they are being read now or plotted from an hour ago, so the reading beside a sparkline is in the units the line is drawn in.

These readings change once a minute and the badge polls once a second, so they are declared slow: the host sends them when they change and the badge holds on to them in between. Watching six domains costs about 1.7KB a second on the wire without that, and nothing with it.

One request covers every domain at once, however many are ticked, so the GraphQL API's limit of 300 queries in five minutes is nowhere in sight at a request a minute.

The domain list is kept between runs, so the checkboxes are there before the first fetch lands and a save made while the network is down does not lose which ones you had ticked.
