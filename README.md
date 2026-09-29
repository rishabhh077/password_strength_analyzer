# Password Strength Analyzer & Breach Checker

A static, client-side web app that analyzes password strength in real
time, estimates entropy, flags weak/common patterns, checks a password
against known data breaches (without ever sending it anywhere in full),
checks for password reuse, and generates strong replacement passwords.

**Live site:** https://rishabhh077.github.io/password_strength_analyzer/

Everything runs entirely in the browser. There is no backend, no
build step, and no framework — just HTML5, CSS3, and vanilla
JavaScript.

## Project structure

```
password_strength_analyzer/
├── index.html   # Markup only — links style.css and script.js
├── style.css    # All styling, organized into sections
├── script.js    # All application logic
├── backup/      # Snapshot(s) of the original single-file version
└── README.md
```

## Technologies used

- **HTML5** — semantic structure (`<main>`, `<section>`, `<footer>`, labelled
  form controls, ARIA live regions for dynamic status messages).
- **CSS3** — the original dark UI theme, layout, animations, and the
  responsive breakpoint, unchanged in appearance.
- **Vanilla JavaScript (ES2017+)** — no frameworks, no libraries, no
  build tooling.

### Browser APIs used

| API | Where it's used |
|---|---|
| **Web Crypto API** (`crypto.subtle.digest`, `crypto.getRandomValues`) | SHA-1 hashing for the breach check, SHA-256 hashing for the reuse check, and cryptographically strong randomness for the password generator. |
| **Fetch API** (`fetch`) | Calling the Have I Been Pwned Pwned Passwords "range" endpoint, with request timeout/abort handling via `AbortController`. |
| **DOM API** (`getElementById`, `querySelector`, `addEventListener`, `textContent`, `classList`, `style`) | Reading input, updating the strength dial, verdict, checklist, and status panels live as you type. |
| **Clipboard API** (`navigator.clipboard.writeText`) | Copying a generated password, with a visible success/failure indicator. |

## How the breach check works (k-anonymity)

The app is called a "Breach Checker" because it performs a **real**
online check against the
[Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords),
using the k-anonymity model the API is designed around:

```
password
   │  SHA-1 (locally, via Web Crypto API)
   ▼
ABCDE123456789...            (full 40-char hash, kept in the browser)
   │  first 5 characters only
   ▼
ABCDE  ───fetch()──▶  GET https://api.pwnedpasswords.com/range/ABCDE
                              │
                              ▼
                    list of "suffix:count" pairs
                    sharing that same 5-char prefix
   │
   ▼
compare the remaining 35 characters of the hash locally
   │
   ▼
display the breach count (or "not found")
```

**Privacy guarantees:**

- The plaintext password **never** leaves the browser.
- The full SHA-1 hash **never** leaves the browser — only the first 5
  hex characters (the "prefix") are sent.
- The API has no way to know which of the hundreds of returned
  suffixes actually belongs to your password; the match is decided
  locally, after the response arrives.
- Nothing about the password is written to `localStorage`,
  `sessionStorage`, a URL, or the console.

## Password reuse checker

The optional "Reuse check" card lets you hash old passwords (SHA-256,
via the Web Crypto API) and keep them in memory for the current tab
session only. When you type a password above, it's hashed the same
way and compared locally against the saved hashes. Saved values are
never written to disk and are cleared when the page is closed or
reloaded.

## Password strength analysis

The checklist and 0–100 score combine:

- Length (12+ characters)
- Character variety (uppercase, lowercase, digit, symbol)
- Absence of sequential runs (`abc`, `123`, `qwe`, …) and 3+ repeated
  characters
- Absence of your name/date-of-birth (optional fields, used only for
  this local check — never saved or sent anywhere)
- Not being on a common/leaked-password shortlist
- Estimated Shannon entropy (`length × log2(character-pool size)`)

Entropy is shown as an estimate of guessing resistance, not an
absolute measure of real-world security — a password can be low-risk
by pattern checks and still appear in a real breach, which is exactly
why the online leak check exists as a separate signal.

## Password generator

Generates a 16-character password guaranteeing at least one
lowercase letter, uppercase letter, digit, and symbol, using
`crypto.getRandomValues()` for all randomness (not `Math.random()`,
which is not appropriate for anything security-sensitive). The result
can be copied with one click via the Clipboard API.

## Running locally

No build step or dependencies are required.

1. Clone or download this repository.
2. Open `index.html` directly in a modern browser, **or** serve the
   folder with any static file server, for example:
   ```bash
   npx serve .
   # or
   python3 -m http.server 8000
   ```
3. The breach checker needs internet access (to reach
   `api.pwnedpasswords.com`) and a secure context — this works
   automatically over `https://` (GitHub Pages) or on `localhost`.

## Deploying to GitHub Pages

This is a static site with only relative asset paths
(`style.css`, `script.js`), so it works on GitHub Pages with no
configuration beyond enabling Pages for this repository (Settings →
Pages → Deploy from branch → `main` / root).

## Browser support

Any modern browser with support for the Web Crypto API and the Fetch
API (current Chrome, Firefox, Safari, Edge).

## Software & hardware requirements

- **OS:** Windows 10/11, Linux, or macOS
- **Browser:** Any modern browser supporting JavaScript and the Web
  Crypto API
- **Dev environment:** Visual Studio Code or any code editor
- **Version control:** Git and GitHub
- **Hardware:** Dual-core processor or better, 4 GB RAM minimum (8 GB
  recommended), ~1 GB free storage for tooling, a standard display,
  and an internet connection for GitHub access and the online leak
  check.
