# Atlas Security Watch (ASW)

A free, self-updating dashboard of national-security news from every continent, region and country.
Headlines are sorted by **place** (continent → region → country) and by **domain**: armed conflict, terrorism, political stability, cyber, diplomacy and sanctions, economic and energy security, maritime, nuclear/WMD, organised crime, health and humanitarian, disasters, borders and migration, and space and emerging tech.

It runs entirely on GitHub's free services. Your laptop is only needed to set it up.

- **GitHub Actions** collects the news every ~20 minutes from about 90 news feeds in 17 languages, Google News (English plus 12 other languages), Bing News, and GDELT's 15-minute event files. Non-English headlines are translated to English automatically, for free and offline.
- **GitHub Pages** hosts the dashboard at `https://YOUR-USERNAME.github.io/security-watch/`.

---

## Setup (about 15 minutes, all in your web browser)

### 1. Create a GitHub account
Go to [github.com](https://github.com) and sign up (free).

### 2. Create the repository
1. Click **+** (top right) → **New repository**.
2. Name it `security-watch`.
3. Choose **Public**. This keeps GitHub Actions free and unlimited.
4. Tick **Add a README file**.
5. Click **Create repository**.

### 3. Turn on the website
1. In your new repository, click **Settings** (top bar) → **Pages** (left menu).
2. Under **Build and deployment → Source**, choose **GitHub Actions**.

That's all on this screen. There's nothing to save.

### 4. Upload the files
1. Unzip `security-watch.zip` on your computer.
2. Back on the repository's main page, click **Add file → Upload files**.
3. Open the unzipped `security-watch` folder, select **everything inside it** (not the folder itself), and drag it into the upload box. The folders `config`, `scripts`, `site` and `setup` must appear in the list.
4. Click **Commit changes**.

### 5. Add the schedule file
Mac and some Windows setups hide folders whose names start with a dot, so the `.github` folder is usually left out of the upload. Add it by hand:

1. Click **Add file → Create new file**.
2. In the name box, type exactly `.github/workflows/update.yml`. The slashes create the folders automatically.
3. Open `setup/update.yml` in your repository (or in the unzipped folder), copy all of it, and paste it into the big text box.
4. Click **Commit changes**.

*(If `.github` did upload in step 4, skip this step.)*

### 6. Watch the first run
1. Click the **Actions** tab. A run called **Update dashboard** will be working (yellow dot).
2. After 2–4 minutes it turns green.
3. Open `https://YOUR-USERNAME.github.io/security-watch/`, replacing `YOUR-USERNAME` with your GitHub username.

Bookmark it, or set it as your browser's start page. It updates itself from now on.

> If no run started on its own: **Actions → Update dashboard → Run workflow → Run workflow**.

---

## Using the dashboard

| Part | What it does |
|---|---|
| **Places** (left) | Every continent, region and country with report counts. A red dot means high-priority reports. Click to filter. Hover a country and click ☆ to add it to your watchlist. "Show quiet" also lists countries with nothing right now. |
| **Briefing** | Totals, a **Pulse** grid (continent × domain; click any cell), **Hotspots** (the busiest countries) and **Top stories** (the most severe and most widely reported, spread across regions, with places kept for `focus_regions` in `config/sources.yaml`). |
| **Feed** | All reports, newest first. Filter by topic, time window (1h–48h), "High priority only", or search words. "+N outlets" shows other publishers covering the same story. |
| **Watchlist** | Only the countries and regions you starred. It's saved in your browser. |
| **Links** | Your start page: live maps, trackers, institutions and think tanks. |
| **Sources** | Health of every source from the last run. |

The red bar on a report means high priority (casualties, coups, strikes, major quakes). Amber means elevated.

The page checks for new data every 5 minutes and offers to show it. Any filtered view can be bookmarked, because the address bar keeps the filters.

---

## Customising it

Edit files directly on github.com: open a file, click the ✏️ pencil, change it, then click **Commit changes**. The dashboard rebuilds within a few minutes.

| File | What to change |
|---|---|
| `config/sources.yaml` | Add or remove RSS feeds, Google News searches, GDELT searches and Links-tab entries. It also holds the time window (`window_hours`). |
| `config/domains.yaml` | Keywords for each domain, severity words, and the noise filter that drops sport and entertainment. |
| `config/places.yaml` | Countries, regions, and the words that point to them: cities, demonyms, armed groups. |
| `config/corrections.yaml` | Fix a wrongly tagged place. Click **Wrong place?** on a story to get a ready-made line to paste here. Rules for repeating mistakes, such as Niger State being tagged as Niger, also live here. |

**Adding a source:** copy one line under `feeds:` and change the name and URL. Use `specialist: true` for outlets that only cover security, and set a `hint:` (a place name from `places.yaml`) if the outlet covers one country or region.

**Other languages:** add a feed with `lang: xx` (e.g. `lang: fr`), or add an edition under `google_news → editions` with its own search words in that language. Headlines are translated automatically. Translation uses free open-source [Argos Translate](https://www.argosopentech.com) models, which cover about 50 languages into English, including Arabic, Chinese, French, Spanish, Portuguese, Russian, Ukrainian, Persian, Turkish, Hindi, Urdu, Indonesian, Swahili, Japanese and Korean. Hausa, Somali and Amharic have no free model yet.

**Translation on the page:** translated headlines show a small badge such as **fr → en**. Click it to see the original. Use the language menu next to "High priority only" to show English sources only, other languages only, or one language.

---

## Good to know

- **Refresh rate:** every 20 minutes, though GitHub sometimes runs a few minutes late at busy times.
- **Accuracy:** tagging is automatic and keyword-based, so some items will be mis-filed. The **Sources** tab and these config files are how you tune it.
- **GDELT and Google News** are wide nets. Curated feeds are listed first when the same story appears in several places.
- **It stays alive on its own:** GitHub pauses schedules on inactive repositories after 60 days, so the workflow writes a one-line `keepalive.txt` once a month to prevent that.
- **Public:** the repository and the page are public. They only contain public news headlines.
- **Cost:** free. Actions minutes are unlimited for public repositories.

## Troubleshooting

| Problem | Fix |
|---|---|
| Page says **"No data yet"** or shows a 404 | Check **Settings → Pages → Source** is **GitHub Actions**, then **Actions → Update dashboard → Run workflow**. |
| A run fails at **deploy** | Same as above: the Pages source must be **GitHub Actions**. |
| A run fails at the **keep-alive** step | **Settings → Actions → General → Workflow permissions →** select **Read and write permissions**, then save. |
| Some sources show red on the Sources tab | That outlet changed or removed its feed. Find its new RSS address, or delete that line. Everything else keeps working. |
| "Updates may be paused" at the top | Open **Actions**. If the workflow was disabled, click **Enable workflow**. |
