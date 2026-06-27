/* ================================================================
   SPLK-5002 Mock Exam — App Logic
   ================================================================ */

const TOTAL_Q = 60;
const PASSING_SCORE = 0.70;
const EXAM_SECONDS = 90 * 60; // 90 minutes (real exam duration)
const WARNING_SECONDS = 10 * 60;

const DOMAINS = {
  'Detection Engineering':          0.40,
  'Security Processes and Programs': 0.20,
  'Automation and Efficiency':       0.20,
  'Data Engineering':                0.10,
  'Auditing and Reporting':          0.10,
};

let state = {
  mode: null,
  questions: [],
  currentIndex: 0,
  answers: {},       // { questionIndex: optionIndex | -1 for skip }
  timerInterval: null,
  timeLeft: EXAM_SECONDS,
  warned: false,
};

/* ================================================================
   HELPERS
   ================================================================ */
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function fmt(seconds) {
  const m = Math.floor(seconds / 60).toString().padStart(2, '0');
  const s = (seconds % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setHTML(html) {
  document.getElementById('app').innerHTML = html;
}

/* ================================================================
   QUESTION SELECTION — stratified random
   ================================================================ */
function pickQuestions() {
  const selected = [];
  const used = new Set();

  for (const [domain, weight] of Object.entries(DOMAINS)) {
    const target = Math.round(TOTAL_Q * weight);
    const pool = shuffle(window.QUESTIONS.filter(q => q.domain === domain));
    const picked = pool.slice(0, Math.min(target, pool.length));
    picked.forEach(q => { used.add(q.id); selected.push(q); });
  }

  // Fill gaps caused by rounding
  if (selected.length < TOTAL_Q) {
    const rest = shuffle(window.QUESTIONS.filter(q => !used.has(q.id)));
    const need = TOTAL_Q - selected.length;
    selected.push(...rest.slice(0, need));
  }

  return shuffle(selected.slice(0, TOTAL_Q));
}

/* ================================================================
   HOME SCREEN
   ================================================================ */
function renderHome() {
  clearTimer();
  state.mode = null;

  const domainRows = Object.entries(DOMAINS).map(([name, w]) => `
    <div class="domain-item">
      <span class="domain-name">${esc(name)}</span>
      <div class="domain-bar-track">
        <div class="domain-bar-fill" style="width:${w * 100}%"></div>
      </div>
      <span class="domain-pct">${Math.round(w * 100)}%</span>
    </div>
  `).join('');

  setHTML(`
    <div class="screen home-screen">
      <header class="app-header">
        <div class="logo">
          <div class="logo-icon">S</div>
          <div class="logo-text">
            <span class="logo-title">SPLK-5002</span>
            <span class="logo-sub">Mock Exam</span>
          </div>
        </div>
        <div class="exam-stats">
          <span class="stat"><strong>200</strong> questions</span>
          <span class="stat-sep">·</span>
          <span class="stat"><strong>60</strong> per session</span>
          <span class="stat-sep">·</span>
          <span class="stat"><strong>70%</strong> to pass</span>
          <span class="stat-sep">·</span>
          <span class="stat"><strong>90 min</strong> (exam)</span>
        </div>
      </header>

      <main class="home-main">
        <div class="home-hero">
          <div class="cert-badge">SPLK-5002</div>
          <h1 class="home-title">Splunk Certified<br>Cybersecurity Defense Engineer</h1>
          <p class="home-subtitle">Practice with 200 exam-quality questions across all official domains</p>
        </div>

        <div class="mode-cards">
          <div class="mode-card practice-card">
            <span class="mode-card-tag tag-practice">Study</span>
            <span class="mode-icon">📚</span>
            <h2>Practice Mode</h2>
            <p>Instant answer feedback with full explanations for every option</p>
            <ul class="mode-features">
              <li>60 stratified random questions</li>
              <li>Immediate correct / wrong feedback</li>
              <li>Explanation for each answer option</li>
              <li>Running score visible throughout</li>
            </ul>
            <button class="mode-btn practice-btn" onclick="startSession('practice')">Start Practice →</button>
          </div>

          <div class="mode-card exam-card">
            <span class="mode-card-tag tag-exam">Timed</span>
            <span class="mode-icon">🎯</span>
            <h2>Exam Mode</h2>
            <p>Authentic exam simulation with countdown timer and end-of-session scoring</p>
            <ul class="mode-features">
              <li>60 stratified random questions</li>
              <li>90-minute countdown timer</li>
              <li>No hints or feedback during exam</li>
              <li>Full review and analytics at the end</li>
            </ul>
            <button class="mode-btn exam-btn" onclick="startSession('exam')">Start Exam →</button>
          </div>
        </div>

        <div class="domain-overview">
          <p class="section-label">Exam Domains &amp; Weights</p>
          <div class="domain-list">${domainRows}</div>
        </div>
      </main>
    </div>
  `);
}

/* ================================================================
   SESSION
   ================================================================ */
function startSession(mode) {
  state.mode = mode;
  state.questions = pickQuestions();
  state.currentIndex = 0;
  state.answers = {};
  state.timeLeft = EXAM_SECONDS;
  state.warned = false;

  if (mode === 'exam') startTimer();
  renderQuestion(0);
}

/* ================================================================
   QUESTION RENDER
   ================================================================ */
function renderQuestion(index) {
  const q = state.questions[index];
  const total = state.questions.length;
  const isAnswered = state.answers.hasOwnProperty(index);
  const isLast = index === total - 1;
  const progressPct = (index / total) * 100;

  const correctCount = Object.entries(state.answers)
    .filter(([i, a]) => a !== -1 && state.questions[+i].correct === a).length;
  const answeredCount = Object.values(state.answers).filter(a => a !== -1).length;

  // Header right
  let headerRight = '';
  if (state.mode === 'practice' && answeredCount > 0) {
    headerRight += `<span class="score-chip">${correctCount} / ${answeredCount}</span>`;
  }
  if (state.mode === 'exam') {
    headerRight += `<span class="timer-chip${state.timeLeft <= WARNING_SECONDS ? ' warning' : ''}" id="timer-chip">${fmt(state.timeLeft)}</span>`;
  }

  // Options
  const optionsHTML = q.options.map((opt, i) => {
    let cls = 'option-btn';
    let resultIcon = '';

    if (isAnswered) {
      const userAns = state.answers[index];
      if (state.mode === 'practice') {
        if (i === q.correct) {
          cls += ' correct';
          resultIcon = '<span class="option-result-icon">✓</span>';
        } else if (i === userAns) {
          cls += ' wrong';
          resultIcon = '<span class="option-result-icon">✗</span>';
        }
      } else {
        // exam mode: just show selected
        if (i === userAns) cls += ' selected';
      }
      cls += ' disabled';
    }

    const expl = (isAnswered && state.mode === 'practice')
      ? `<div class="option-explanation">${esc(q.explanations[i])}</div>` : '';

    return `
      <button class="${cls}" onclick="selectOption(${i})">
        <span class="option-letter">${String.fromCharCode(65 + i)}</span>
        <div class="option-content">
          <span class="option-text">${esc(opt)}</span>
          ${expl}
        </div>
        ${resultIcon}
      </button>`;
  }).join('');

  // Navigation
  let navHTML = '';
  if (state.mode === 'practice') {
    if (isAnswered) {
      navHTML = `<button class="next-btn" onclick="${isLast ? 'finishSession()' : 'nextQuestion()'}">${isLast ? 'View Results →' : 'Next Question →'}</button>`;
    }
  } else {
    // exam: always show next/submit
    const unanswered = !isAnswered ? '<span class="unanswered-warning">⚠ Unanswered</span>' : '';
    navHTML = `${unanswered}<button class="next-btn" onclick="${isLast ? 'finishSession()' : 'nextQuestion()'}">
      ${isLast ? 'Submit Exam →' : 'Next →'}
    </button>`;
  }

  setHTML(`
    <div class="screen question-screen">
      <header class="question-header">
        <button class="back-btn" onclick="confirmHome()">← <span>Home</span></button>
        <div class="header-center">
          <span class="mode-chip">${state.mode === 'practice' ? '📚 Practice' : '🎯 Exam'}</span>
          <span class="q-counter">Question ${index + 1} of ${total}</span>
        </div>
        <div class="header-right">${headerRight}</div>
      </header>

      <div class="progress-track">
        <div class="progress-fill" style="width:${progressPct}%"></div>
      </div>

      <main class="question-main">
        <div class="question-card">
          <div class="q-domain-tag">${esc(q.domain)}</div>
          <div class="question-text">${esc(q.question)}</div>
          <div class="options-list">${optionsHTML}</div>
          <div class="question-nav">${navHTML}</div>
        </div>
      </main>
    </div>
  `);
}

function selectOption(optionIndex) {
  const index = state.currentIndex;
  if (state.answers.hasOwnProperty(index)) return;

  state.answers[index] = optionIndex;
  renderQuestion(index);
}

function nextQuestion() {
  if (state.currentIndex < state.questions.length - 1) {
    // In exam mode, record unanswered as skip
    if (state.mode === 'exam' && !state.answers.hasOwnProperty(state.currentIndex)) {
      state.answers[state.currentIndex] = -1;
    }
    state.currentIndex++;
    renderQuestion(state.currentIndex);
  } else {
    finishSession();
  }
}

function confirmHome() {
  if (state.mode === 'exam' && state.timerInterval) {
    if (!confirm('Exit exam? Your progress will be lost.')) return;
  }
  renderHome();
}

/* ================================================================
   TIMER
   ================================================================ */
function startTimer() {
  clearTimer();
  state.timerInterval = setInterval(() => {
    state.timeLeft = Math.max(0, state.timeLeft - 1);

    const chip = document.getElementById('timer-chip');
    if (chip) {
      chip.textContent = fmt(state.timeLeft);
      if (state.timeLeft <= WARNING_SECONDS) chip.classList.add('warning');
    }

    if (!state.warned && state.timeLeft <= WARNING_SECONDS) {
      state.warned = true;
      showToast('⚠️  10 minutes remaining!', true);
    }

    if (state.timeLeft === 0) {
      clearTimer();
      showToast('⏰  Time is up! Submitting exam…', true);
      setTimeout(finishSession, 1500);
    }
  }, 1000);
}

function clearTimer() {
  if (state.timerInterval) {
    clearInterval(state.timerInterval);
    state.timerInterval = null;
  }
}

/* ================================================================
   TOAST
   ================================================================ */
function showToast(msg, isWarn = false) {
  let t = document.querySelector('.toast');
  if (!t) {
    t = document.createElement('div');
    t.className = 'toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.className = 'toast' + (isWarn ? ' warn' : '');
  requestAnimationFrame(() => t.classList.add('visible'));
  clearTimeout(t._to);
  t._to = setTimeout(() => {
    t.classList.remove('visible');
    setTimeout(() => t.remove(), 300);
  }, 3200);
}

/* ================================================================
   RESULTS
   ================================================================ */
function finishSession() {
  clearTimer();
  renderResults();
}

function computeResults() {
  const { questions, answers, mode, timeLeft } = state;
  let correct = 0;
  const domainStats = {};

  questions.forEach((q, i) => {
    const ans = answers[i];
    const hit = ans !== undefined && ans !== -1 && ans === q.correct;
    if (hit) correct++;

    if (!domainStats[q.domain]) domainStats[q.domain] = { correct: 0, total: 0 };
    domainStats[q.domain].total++;
    if (hit) domainStats[q.domain].correct++;
  });

  return {
    correct,
    total: questions.length,
    pct: (correct / questions.length) * 100,
    passed: (correct / questions.length) >= PASSING_SCORE,
    domainStats,
    timeTaken: mode === 'exam' ? EXAM_SECONDS - timeLeft : null,
  };
}

function renderResults() {
  const res = computeResults();
  const pctRound = Math.round(res.pct);
  const r = 60;
  const circ = 2 * Math.PI * r;
  const fillOffset = circ - (res.pct / 100) * circ;

  // Domain rows
  const domainHTML = Object.entries(res.domainStats).map(([domain, s]) => {
    const p = Math.round((s.correct / s.total) * 100);
    const cls = p >= 70 ? 'pct-good' : p >= 50 ? 'pct-ok' : 'pct-poor';
    const barColor = p >= 70 ? 'var(--green)' : p >= 50 ? 'var(--yellow)' : 'var(--red)';
    return `
      <tr>
        <td>${esc(domain)}</td>
        <td>
          <div class="domain-mini-bar">
            <div class="domain-mini-track">
              <div class="domain-mini-fill" style="width:${p}%;background:${barColor}"></div>
            </div>
          </div>
        </td>
        <td>${s.correct} / ${s.total}</td>
        <td><span class="pct-pill ${cls}">${p}%</span></td>
      </tr>`;
  }).join('');

  // Time row
  const timeRow = res.timeTaken !== null ? `
    <div class="result-stat-item">
      <span class="result-stat-label">Time Taken</span>
      <span class="result-stat-value">${fmt(res.timeTaken)}</span>
    </div>` : '';

  // Review items
  const reviewHTML = state.questions.map((q, i) => {
    const ans = state.answers[i];
    const skipped = ans === undefined || ans === -1;
    const isCorrect = !skipped && ans === q.correct;
    const cls = skipped ? 'is-skipped' : isCorrect ? 'is-correct' : 'is-wrong';
    const icon = skipped ? '–' : isCorrect ? '✓' : '✗';

    const optsHTML = q.options.map((opt, j) => {
      let cls2 = 'review-option r-neutral';
      let badge = '';
      if (j === q.correct) { cls2 = 'review-option r-correct'; badge = '<span class="review-badge badge-correct">✓ Correct</span>'; }
      if (!skipped && j === ans && j !== q.correct) { cls2 = 'review-option r-wrong'; badge = '<span class="review-badge badge-yours">Your answer</span>'; }
      if (skipped && j === q.correct) badge += '<span class="review-badge badge-skipped">Skipped</span>';

      return `
        <div class="${cls2}">
          <span class="review-opt-letter">${String.fromCharCode(65 + j)}</span>
          <div class="review-opt-body">
            <div class="review-opt-text">${esc(opt)}</div>
            <div class="review-opt-expl">${esc(q.explanations[j])}</div>
          </div>
          ${badge}
        </div>`;
    }).join('');

    return `
      <div class="review-item ${cls}" id="ri-${i}">
        <div class="review-header" onclick="toggleReview(${i})">
          <span class="review-status-icon">${icon}</span>
          <span class="review-q-num">Q${i + 1}</span>
          <span class="review-q-snippet">${esc(q.question.substring(0, 90))}${q.question.length > 90 ? '…' : ''}</span>
          <span class="review-chevron" id="rc-${i}">▼</span>
        </div>
        <div class="review-body" id="rb-${i}">
          <div class="review-domain-tag">${esc(q.domain)}</div>
          <div class="review-question-full">${esc(q.question)}</div>
          <div class="review-options-list">${optsHTML}</div>
        </div>
      </div>`;
  }).join('');

  setHTML(`
    <div class="screen results-screen">
      <header class="results-header">
        <button class="back-btn" onclick="renderHome()">← <span>Home</span></button>
        <span class="mode-chip">Results — ${state.mode === 'practice' ? '📚 Practice' : '🎯 Exam'}</span>
        <div></div>
      </header>

      <main class="results-main">
        <div class="results-hero">
          <div class="score-dial-wrap">
            <svg class="score-dial" viewBox="0 0 140 140">
              <circle cx="70" cy="70" r="${r}" class="dial-track"/>
              <circle cx="70" cy="70" r="${r}" class="dial-fill ${res.passed ? 'pass' : 'fail'}"
                style="stroke-dasharray:${circ.toFixed(2)};stroke-dashoffset:${circ.toFixed(2)}"
                data-target="${fillOffset.toFixed(2)}"/>
            </svg>
            <div class="dial-center">
              <span class="dial-pct">${pctRound}%</span>
              <span class="dial-fraction">${res.correct}/${res.total}</span>
            </div>
          </div>

          <div class="results-info">
            <div class="verdict-badge ${res.passed ? 'verdict-pass' : 'verdict-fail'}">
              ${res.passed ? '🎉 PASS' : '❌ FAIL'}
            </div>
            <div class="result-stats-row">
              <div class="result-stat-item">
                <span class="result-stat-label">Score</span>
                <span class="result-stat-value ${res.passed ? 'good' : 'bad'}">${pctRound}%</span>
              </div>
              <div class="result-stat-item">
                <span class="result-stat-label">Correct</span>
                <span class="result-stat-value">${res.correct} / ${res.total}</span>
              </div>
              <div class="result-stat-item">
                <span class="result-stat-label">Passing</span>
                <span class="result-stat-value">70%</span>
              </div>
              ${timeRow}
            </div>
            <div class="result-actions">
              <button class="mode-btn practice-btn" onclick="tryAgain()">Try Again</button>
              <button class="mode-btn ghost-btn" onclick="renderHome()">Home</button>
            </div>
          </div>
        </div>

        <div class="domain-results-section">
          <h3 class="section-title">Performance by Domain</h3>
          <table class="domain-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th style="width:140px">Progress</th>
                <th style="width:90px">Score</th>
                <th style="width:80px">Result</th>
              </tr>
            </thead>
            <tbody>${domainHTML}</tbody>
          </table>
        </div>

        <div class="review-section">
          <h3 class="section-title">Review All Questions</h3>
          <div class="review-list">${reviewHTML}</div>
        </div>
      </main>
    </div>
  `);

  // Animate dial
  requestAnimationFrame(() => {
    setTimeout(() => {
      const fill = document.querySelector('.dial-fill');
      if (fill) fill.style.strokeDashoffset = fill.dataset.target;
    }, 80);
  });
}

function toggleReview(i) {
  const body = document.getElementById(`rb-${i}`);
  const chevron = document.getElementById(`rc-${i}`);
  const open = body.classList.toggle('open');
  chevron.style.transform = open ? 'rotate(180deg)' : '';
}

function tryAgain() {
  startSession(state.mode);
}

/* ================================================================
   INIT
   ================================================================ */
document.addEventListener('DOMContentLoaded', renderHome);
