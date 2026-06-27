# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A vanilla HTML/CSS/JS mock exam app for the SPLK-5002 (Splunk Certified Cybersecurity Defense Engineer) certification. No framework, no build step — open `index.html` directly in a browser.

## Running the App

```bash
open index.html          # macOS
python3 -m http.server   # or serve via local HTTP to avoid file:// CORS quirks
```

**Prerequisite:** `questions.js` must exist alongside `index.html`. It is not committed to the repo but is loaded as the first script in `index.html`. It must expose a global `window.QUESTIONS` array.

## Architecture

The entire app is three files:

- **`index.html`** — shell with a single `<div id="app">` mount point; loads `questions.js` then `app.js`
- **`style.css`** — dark theme using CSS custom properties (`--bg`, `--surface`, `--green`, `--red`, etc. defined in `:root`); no preprocessor
- **`app.js`** — all logic in one file; renders UI by replacing `#app.innerHTML` (no virtual DOM)

### State

A single global `state` object in `app.js` holds everything:

```js
{ mode, questions, currentIndex, answers, timerInterval, timeLeft, warned }
```

`answers` maps question index → selected option index, or `-1` for skipped.

### Screens

Three render functions drive the three screens. Each calls `setHTML()` which replaces `#app`:

| Function | Screen |
|---|---|
| `renderHome()` | Landing / mode selection |
| `renderQuestion(index)` | Single question view |
| `renderResults()` | Post-session score + review |

### Question Selection

`pickQuestions()` does **stratified random sampling**: for each domain it shuffles the domain's pool and picks `round(60 × domainWeight)` questions. Any rounding gap is filled from the remaining pool. Final 60 questions are re-shuffled. Domain weights are defined in the `DOMAINS` constant at the top of `app.js`.

### Modes

- **Practice** — immediate correct/wrong feedback + per-option explanations after each answer; running score chip visible in header
- **Exam** — 90-minute countdown timer; no feedback during session; full review unlocked on results screen; unanswered questions are auto-recorded as `-1` skips when advancing

### `window.QUESTIONS` Schema

Each question object in the array must have:

```js
{
  id: string,           // unique identifier
  domain: string,       // must match a key in DOMAINS exactly
  question: string,
  options: string[],    // 4 items
  correct: number,      // 0-based index into options
  explanations: string[] // 4 items, one per option
}
```

Domain values must exactly match the keys in `DOMAINS`:
- `"Detection Engineering"` (40%)
- `"Security Processes and Programs"` (20%)
- `"Automation and Efficiency"` (20%)
- `"Data Engineering"` (10%)
- `"Auditing and Reporting"` (10%)
