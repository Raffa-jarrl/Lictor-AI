# ISP response — scanning inquiry

A short, factual reply to send your ISP to close the ticket. Fill the
`[brackets]`. Keep it calm and cooperative — they just want to know it's not
a compromised machine and that you'll be a good neighbor. It isn't, and you
will.

---

**Subject:** Re: outbound traffic inquiry — account [your account #]

Hi [ISP / NOC contact],

Thanks for reaching out. I can confirm the traffic you noticed is **not** a
compromised machine — it's **independent security research** I run, and I've
already reduced it.

**What it is.** I look for *publicly exposed* security problems (leaked
credentials, exposed config files, subdomain takeovers) and privately notify
the owners so they can fix them before criminals do. It's responsible
disclosure — read-only, detection-only. I never exploit anything, never
download data, never run brute-force or denial-of-service tests.

**What I've already changed** (as of [date]):
- Consolidated everything to **one rate-limited scanner** instead of several
  parallel jobs — the burst pattern you saw is gone.
- Moved most discovery to **passive sources** (certificate-transparency logs,
  passive DNS) that don't touch third-party hosts at all.
- **Rate-limited DNS** and spread it across public resolvers, so there's no
  query flood.
- Published a public **scanning policy + abuse contact + instant opt-out** at
  `https://lictorai.com/scan-policy`, and an identifiable User-Agent
  (`Lictor-Patrol/1.0`) so anyone can see who we are and reach me.

**Cooperation.** If you'd like, send me any IP ranges or customer domains you
want excluded and I'll add them to my permanent exclusion list immediately.
I'm also happy to share request logs for any period you're curious about.

Going forward this will be low-volume, identifiable, read-only traffic. Happy
to hop on a call if that's easier.

Best,
[Your name]
[Your phone] · abuse@lictorai.com

---

### Notes for you (don't send these)

- If they ask for a **volume cap**, the gentle runner is already throttled;
  you can lower `RATE`/`THREADS` in `scripts/gentle-patrol.sh` further.
- If they're firm about **no scanning from a residential line at all**, that's
  the cue to move active scanning to a **cloud VPS** (the plan once there's
  revenue). Passive-only discovery can keep running from home indefinitely —
  it generates effectively no third-party traffic.
- Keep this cooperative. An ISP that feels respected closes the ticket; one
  that feels stonewalled escalates.
