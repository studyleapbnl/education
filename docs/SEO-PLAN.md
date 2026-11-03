# Study LEAP - SEO / AEO / GEO plan (v9, 30 Oct 2026)

## What was wrong (found 30 Oct)
1. **Conflicting preferred address.** The live site sends `https://www.studyleap.in/...` visitors to `https://studyleap.in/...`,
   but every page, the sitemap and the structured data said the preferred address was `www`. Google saw "this page says its
   real address is www" while www redirected back to the non-www address, so pages got stuck as "Alternate page with proper
   canonical tag" / "Page with redirect". **Fixed:** everything now uses `https://studyleap.in/` (canonical, sitemap,
   robots, llms.txt, schema, social tags, e-mails, IndexNow).
2. **Home page was not about the business's place.** Title/H1 did not say Barnala. **Fixed** (home = Barnala + India;
   /education-loan-punjab/ = the state; /education-loan-barnala/ = the office).
3. **Unverifiable / contradictory claims** ("50+ lenders" vs "8+", "clients typically save Rs 1-3 lakh", "HQ" / "Branch"
   badges on cities you have no office in). Google rates money pages on trust. **Fixed** (8+ everywhere; savings sentence
   and badges removed). Please confirm the real number of lenders.
4. **Broken home markup.** The reviews section was never closed, so the sections below it were squeezed into a 1200px
   box, and the page had no `<main>` landmark. **Fixed.**
5. **Thin site for a brand-new domain.** About 60 pages, most of them near-identical city/bank templates, no backlinks, a
   domain that used to be a music site (old song URLs in Search Console), and a brand name shared with Leap Finance /
   LeapScholar. This is solved by authority and uniqueness, not by more template pages (see below).

## After you upload this version (do these in order, 20 minutes)
1. Cloudflare > Caching > **Purge everything**.
2. Open https://studyleap.in/ , https://studyleap.in/education-loan-punjab/ and https://studyleap.in/education-loan-barnala/
   - they must load, and `https://www.studyleap.in/` must land on `https://studyleap.in/`.
3. Search Console (property studyleap.in):
   - **Sitemaps:** remove the old `https://www.studyleap.in/sitemap.xml` entry, add `https://studyleap.in/sitemap.xml`.
   - **URL inspection** > paste `https://studyleap.in/` > Test live URL > **Request indexing**. Repeat for
     `/education-loan-punjab/`, `/education-loan-barnala/`, `/emi-calculator/`, `/education-loan-eligibility/`,
     `/education-loan-without-collateral/`, `/education-loan-canada/`, `/education-loan-usa/`, `/education-loan-uk/`,
     `/education-loan-australia/` (about 10 per day is the limit).
   - **Settings > Crawl stats / Pages:** check again after 7 days; "Page with redirect" and "Alternate page" counts should fall.
4. **IndexNow (Bing, Yandex and the AI search tools that use them).** After the new worker.js is deployed (PowerShell):
   `Invoke-RestMethod -Method Post -Headers @{'X-CRM-Secret'='YOUR_CRM_SECRET'} -ContentType 'application/json' -Body '{"all":true}' https://api.studyleap.in/indexnow`
5. **Bing Webmaster Tools** (https://www.bing.com/webmasters): sign in, **Import from Google Search Console**, submit the
   sitemap. Bing powers Copilot and a large part of ChatGPT-search / Perplexity-style answers, so this is half of "GEO".

## Google Business Profile (the single biggest lever for "near me" and "Barnala" searches)
Your profile already exists (the review link on the site points to it) - check it is **verified** and owned by you.
- Name exactly `Study LEAP`; category **Loan agency** (add: Educational consultant, Financial consultant if offered).
- Address: SCO No 5, Behind New Bus Stand, Barnala, Punjab 148101. Phone +91 88376 93510. Website `https://studyleap.in/`
  (not www, not a tracking URL). Hours Mon-Sat 9-7 only if true.
- Description (750 chars): who you help, courses/countries, free consultation, Barnala office. No phone numbers or links inside.
- Add services (Education loan for India / Canada / UK / USA / Australia / Germany, Collateral-free loans, Document support).
- Add 10+ real photos (office front, inside, team) and a logo. Post one update a week (a tip, a checklist, an FAQ).
- Reviews: ask every satisfied student/parent, with a WhatsApp message and the review link; reply to every review. Never buy
  or incentivise reviews. Aim for 10 genuine reviews in the first 60 days.
- Keep Name / Address / Phone **identical** everywhere (website footer, Facebook, Instagram, directories).

## Off-page: where links and mentions come from (week by week)
Week 1-2: Facebook page and Instagram profile complete and linked to the site; LinkedIn company page; YouTube channel (even 5
short videos: "documents for an education loan", "collateral explained"). Add all of them to the site footer once they exist
(they are also in the schema `sameAs`).
Week 2-4: Directory listings with identical NAP - Justdial, Sulekha, IndiaMART (service), Yellow Pages India, Foursquare,
Bing Places (import from Google), Apple Maps Connect.
Week 3-6: Local relationships that give real links - IELTS/PTE coaching centres, schools and colleges in Barnala, Sangrur,
Bathinda, Mansa, Moga: offer a free "education loan awareness" session for students and a link from their site/Instagram.
Week 4-8: Q&A presence - answer genuine questions on Quora and Reddit (r/IndianStudents, r/studyAbroad) with useful,
non-promotional answers that link to the matching guide only when relevant.
Ongoing: a short press note for local Punjabi/Hindi news ("education loan awareness camp in Barnala"); student success stories
**with written permission**.

## Content that earns clicks (write for questions people actually ask)
Each article: one clear answer in the first 2 sentences, a short step list or table, sources you can cite (RBI, SBI, Income Tax
Dept, Vidya Lakshmi / PM-Vidyalaxmi portal), "Last updated" date, author name. 800-1,200 words. One per week.
1. Education loan for Canada from Punjab: documents, GIC and how the bank sees it
2. Collateral-free education loan: who gets it and how much, explained simply
3. SBI vs Bank of Baroda vs Punjab National Bank education loan for Punjab students: how to choose
4. Education loan for IELTS 6.0 / 6.5 students: what lenders look at
5. Moratorium period and simple interest: a worked example with real numbers
6. Section 80E: how to claim, with an example and the "old regime only" warning
7. What if my education loan is rejected? 8 reasons and what to do next (extend the existing rejection page)
8. Co-applicant rules: can a farmer / shopkeeper / uncle be a co-applicant?
9. Study in Germany/Ireland/New Zealand on a loan: blocked account vs loan
10. Education loan checklist PDF (a lead magnet) for Punjab families
Do **not** publish more near-identical city pages. If you want Ludhiana, Amritsar, Jalandhar etc., each needs something only
that city has (local colleges, which bank branches handle the loans, a real photo or story) - tell me the facts and I will write it.

## AEO (answer engines) and GEO (AI assistants) checklist
- Question headings + a 40-60 word direct answer under each (done on the Punjab and Barnala pages; extend to the rest).
- Facts stated the same way everywhere: Study LEAP, education loan consultancy, Barnala, Punjab, phone, hours.
- Cite official sources and name them in the text ("according to the Income Tax Department's Section 80E page").
- Keep `llms.txt` current (it lists the pages worth citing); keep AI crawlers allowed in `robots.txt` (they are).
- Get mentioned on sites AI tools read: Google Business Profile, Facebook, LinkedIn, YouTube, Quora, Reddit, directories.
- Do not claim what you cannot show: AI systems and Google both down-rank pages that contradict themselves.

## How to measure (check every Monday)
| Where | What | Month-1 goal | Month-3 goal |
|---|---|---|---|
| Search Console > Pages | Indexed pages | 40+ | all useful pages |
| Search Console > Performance | Impressions (28 days) | 500 | 3,000 |
| Search Console > Performance | Clicks | 15 | 100 |
| GBP > Performance | Calls + direction requests | 5 | 30 |
| GBP | Genuine Google reviews | 3 | 10 |
| Bing Webmaster | Indexed pages | 40+ | all |
Rankings for a new domain normally take 2-4 months to move; these are targets, not promises.

## Test searches (do them in a private window, India)
`site:studyleap.in`, `studyleap.in`, `"Study LEAP" Barnala`, `education loan consultant Barnala`,
`education loan Punjab`, `education loan for Canada Punjab`. Note the date and whether the site appears; repeat monthly.
