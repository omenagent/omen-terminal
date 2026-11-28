/* OMEN Wallet Forensics (v0.8.0)
   Read-only portfolio scan for Robinhood Chain (chain ID 4663).
   Data: Blockscout (holdings, scam reputation, activity), DexScreener (market),
         GoPlus (token security + address threat intel).
   Verdicts reuse the page's own normalize() and scoreToken(), so every token
   gets exactly the same score here as in the main scanner.
   Nothing is signed and nothing is sent anywhere except these public APIs. */
(() => {
'use strict';
const CHAIN_ID = '4663';
const BS = 'https://robinhoodchain.blockscout.com';
const MAX_TOKENS = 20;   // score at most the 20 largest holdings
const DUST_USD = 1;      // holdings worth less than this are listed but not scored (mostly airdropped spam)
const GAP_MS = 1200;     // spacing between GoPlus calls (free tier allows roughly 10 calls a minute)
const RATE_WAIT_S = 30;  // pause when GoPlus answers 4029 "too many requests"
const RATE_RETRIES = 3;

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const isAddr = a => /^0x[a-fA-F0-9]{40}$/.test(a || '');
const short = a => a && a.length > 14 ? a.slice(0, 6) + '…' + a.slice(-4) : (a || '—');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const usd = n => { if (n == null || isNaN(n)) return '—'; const a = Math.abs(n);
  if (a >= 1e9) return '$' + (n / 1e9).toFixed(2) + 'B'; if (a >= 1e6) return '$' + (n / 1e6).toFixed(2) + 'M';
  if (a >= 1e3) return '$' + (n / 1e3).toFixed(1) + 'K'; if (a >= 0.01 || a === 0) return '$' + n.toFixed(2); return '<$0.01'; };
const amt = n => { if (!n) return '0'; const a = Math.abs(n);
  if (a >= 1e9) return (n / 1e9).toFixed(2) + 'B'; if (a >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (a >= 1e3) return (n / 1e3).toFixed(1) + 'K'; if (a >= 1) return n.toLocaleString('en-US', {maximumFractionDigits: 2});
  return n.toPrecision(3); };
const agentLog = (m, c) => { try { if (typeof window.log === 'function') window.log(m, c || ''); } catch (e) {} };

class RateLimited extends Error {}
async function getJSON(url, label) {
  const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 12000);
  try {
    const r = await fetch(url, {signal: ctl.signal, headers: {accept: 'application/json'}});
    if (r.status === 429) throw new RateLimited(`${label} rate limit`);
    if (!r.ok) throw new Error(`${label} HTTP ${r.status}`);
    const d = await r.json();
    if (d && (d.code === 4029 || d.code === '4029')) throw new RateLimited(`${label} rate limit`);
    return d;
  } catch (e) {
    if (e instanceof RateLimited) throw e;
    throw new Error(e.name === 'AbortError' ? `${label} timed out` : e.message);
  } finally { clearTimeout(to); }
}

/* GoPlus token record, waiting out the free-tier rate limit instead of guessing */
async function goplusToken(addr, onWait) {
  for (let i = 0; i <= RATE_RETRIES; i++) {
    try {
      const d = await getJSON(`https://api.gopluslabs.io/api/v1/token_security/${CHAIN_ID}?contract_addresses=${addr}`, 'GoPlus');
      if (d.code !== 1 && d.code !== '1' && !d.result) throw new Error(d.message || 'GoPlus returned no result');
      const res = d.result || {};
      const key = Object.keys(res).find(k => k.toLowerCase() === addr.toLowerCase()) || Object.keys(res)[0];
      return key ? res[key] : null;   // null = GoPlus has no record for this token
    } catch (e) {
      if (!(e instanceof RateLimited) || i === RATE_RETRIES) throw e;
      for (let s = RATE_WAIT_S; s > 0; s--) { onWait(s); await sleep(1000); }
    }
  }
}

/* ---------- styles ---------- */
const css = `
#wallet .wfform{display:flex;gap:8px;flex-wrap:wrap;background:rgba(14,16,19,.92);border:1px solid var(--line2);border-radius:8px;padding:6px}
#wallet .wfform input{flex:1 1 280px;height:46px;background:transparent;border:0;outline:0;padding:0 12px;font:15px var(--mono);color:var(--ivory)}
#wallet .wfform input::placeholder{color:var(--dim)}
#wallet .wfstats{margin-top:16px}
.wfgrid{display:grid;grid-template-columns:minmax(0,1.75fr) minmax(0,1fr);gap:14px;margin-top:14px}
@media (max-width:1000px){.wfgrid{grid-template-columns:minmax(0,1fr)}}
.wfrow{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(0,.8fr) minmax(0,.7fr) 168px 74px;gap:10px;align-items:center;padding:10px 0;border-top:1px solid var(--line);font-size:14px}
.wfrow.wfhead{font-size:12px;color:var(--dim);border-top:0;padding-top:0}
.wfrow .r{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;white-space:nowrap}
.wftok{display:flex;gap:10px;align-items:center;min-width:0}
.wfic{width:30px;height:30px;border-radius:50%;border:1px solid var(--line2);display:grid;place-items:center;font:600 10px var(--mono);color:var(--silver);background:var(--carbon2);flex:none}
.wfname{min-width:0}
.wfname b{display:block;color:var(--ivory);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.wfname small{display:block;font:11px var(--mono);color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.wfv{display:inline-block;padding:4px 8px;border-radius:4px;font:600 11px var(--mono);border:1px solid;white-space:nowrap;max-width:100%;overflow:hidden;text-overflow:ellipsis}
.wfv.b-idle{color:var(--dim);border-color:var(--line2)}
.wfgo{height:30px;padding:0 10px;border:1px solid var(--line2);background:var(--carbon2);border-radius:4px;font:12px var(--mono);color:var(--ink)}
.wfgo:hover{border-color:var(--slate)}
.wfflags{list-style:none;margin:12px 0 0;padding:0;font:12px var(--mono)}
.wfflags li{padding:6px 0;border-top:1px solid var(--line);color:var(--crimson)}
#wfRep .badge{margin-bottom:14px}
@media (max-width:700px){
  .wfrow{grid-template-columns:minmax(0,1fr) auto}
  .wfrow.wfhead{display:none}
  .wfrow .c-bal{display:none}
}`;

/* ---------- markup ---------- */
const sectionHTML = `
<div class="wrap">
  <div class="sh">
    <div><h2>Wallet Forensics</h2>
      <p class="sub">Connect a wallet, or paste any Robinhood Chain address. OMEN reads the holdings and runs every token through the same scoring engine as the scanner above. Read-only: nothing is signed and nothing leaves the wallet.</p></div>
    <span class="tag live">Live · read-only</span>
  </div>
  <form class="wfform" id="wfForm" autocomplete="off">
    <input id="wfAddr" aria-label="Wallet address" placeholder="0x… wallet address on Robinhood Chain" spellcheck="false">
    <button class="btn" type="button" id="wfUse">Use connected wallet</button>
    <button class="btn primary" type="submit" id="wfBtn">Scan wallet</button>
  </form>
  <div class="status" id="wfStatus" role="status" aria-live="polite"></div>
  <div class="stats wfstats">
    <div class="stat"><small>Portfolio value</small><b id="wfVal">—</b></div>
    <div class="stat"><small>Tokens scored</small><b id="wfN">—</b></div>
    <div class="stat"><small>Value-weighted safety</small><b id="wfSafety">—</b></div>
    <div class="stat"><small>Value in critical tokens</small><b id="wfRisk">—</b></div>
    <div class="stat"><small>Safe · caution · critical</small><b id="wfMix">—</b></div>
  </div>
  <div class="wfgrid">
    <div class="card">
      <div class="ct"><span>Holdings by value</span><span class="mono" id="wfCount">—</span></div>
      <div id="wfRows"><p class="fine">Scan a wallet to see every token it holds, scored.</p></div>
    </div>
    <div class="card">
      <div class="ct"><span>Address reputation</span><span class="mono">GoPlus · Blockscout</span></div>
      <div id="wfRep"><p class="fine">Threat-intel record and on-chain activity for the scanned address.</p></div>
    </div>
  </div>
</div>`;

/* ---------- state ---------- */
let connected = null, busy = false, lastScanned = null, rows = [];

function setStatus(m, err) { const s = $('wfStatus'); if (!s) return; s.textContent = m; s.className = 'status' + (err ? ' err' : ''); }

function rowHTML(r, i) {
  const t = r.token;
  const v = r.res
    ? `<span class="wfv ${r.res.cls}" title="${esc(r.res.verdict)}">${typeof r.res.score === 'number' ? r.res.score + '/100 · ' : ''}${esc(r.res.verdict.split(' — ')[0])}</span>`
    : `<span class="wfv b-idle">${esc(r.state || 'Queued')}</span>`;
  const why = r.res && r.res.d && r.res.d.length
    ? r.res.d.slice(0, 2).map(x => x[0]).join(' · ')
    : (r.res ? 'No deductions' : t.name || '');
  return `<div class="wfrow">
    <div class="wftok"><div class="wfic">${esc((t.symbol || '?').slice(0, 4))}</div>
      <div class="wfname"><b>$${esc(t.symbol || '?')}</b><small title="${esc(why)}">${esc(why)}</small></div></div>
    <div class="r c-bal">${esc(amt(r.bal))}</div>
    <div class="r c-val">${esc(usd(r.val))}</div>
    <div>${v}</div>
    <div class="r">${r.native ? '' : `<button class="wfgo" type="button" data-i="${i}" aria-label="Full forensic scan of ${esc(t.symbol || 'token')}">Full ↗</button>`}</div>
  </div>`;
}

function renderRows(extra) {
  const head = `<div class="wfrow wfhead"><span>Token · main finding</span><span class="r c-bal">Balance</span><span class="r c-val">Value</span><span>Verdict</span><span></span></div>`;
  $('wfRows').innerHTML = rows.length
    ? head + rows.map(rowHTML).join('') + (extra ? `<p class="fine">${esc(extra)}</p>` : '')
    : '<p class="fine">This address holds no ERC-20 tokens on Robinhood Chain.</p>';
}

function renderSummary() {
  const scored = rows.filter(r => r.res && !r.native && !r.dust);
  const total = rows.reduce((s, r) => s + (r.val || 0), 0);
  const wv = scored.filter(r => r.val > 0 && typeof r.res.score === 'number');
  const wsum = wv.reduce((s, r) => s + r.val, 0);
  const safety = wsum ? wv.reduce((s, r) => s + r.res.score * r.val, 0) / wsum : null;
  const crit = scored.filter(r => r.res.cls === 'b-crit');
  const n = c => scored.filter(r => r.res.cls === c).length;
  $('wfVal').textContent = usd(total);
  $('wfN').textContent = scored.length + ' / ' + rows.filter(r => !r.native && !r.dust).length;
  $('wfSafety').textContent = safety == null ? '—' : Math.round(safety) + '/100';
  $('wfSafety').style.color = safety == null ? '' : safety >= 75 ? 'var(--sage)' : safety >= 45 ? 'var(--amber)' : 'var(--crimson)';
  $('wfRisk').textContent = usd(crit.reduce((s, r) => s + (r.val || 0), 0));
  $('wfRisk').style.color = crit.length ? 'var(--crimson)' : '';
  $('wfMix').textContent = `${n('b-safe')} · ${n('b-caut')} · ${n('b-crit')}`;
}

/* ---------- address reputation ---------- */
const THREATS = {cybercrime:'Cybercrime', money_laundering:'Money laundering', financial_crime:'Financial crime',
  darkweb_transactions:'Darkweb transactions', phishing_activities:'Phishing activity', stealing_attack:'Stealing attack',
  blackmail_activities:'Blackmail', sanctioned:'Sanctioned address', malicious_mining_activities:'Malicious mining',
  mixer:'Mixer usage', fake_token:'Fake token involvement', honeypot_related_address:'Honeypot-related',
  number_of_malicious_contracts_created:'Malicious contracts created', fake_kyc:'Fake KYC', blacklist_doubt:'Blacklist suspicion',
  gas_abuse:'Gas abuse', reinit:'Reinit attack', fake_standard_interface:'Fake standard interface'};

function renderRep(addr, gp, info, counters) {
  const flags = gp ? Object.keys(THREATS).filter(k => gp[k] != null && gp[k] !== '' && gp[k] !== '0').map(k => THREATS[k] + (k === 'number_of_malicious_contracts_created' ? ` (${gp[k]})` : '')) : null;
  if (info && info.is_scam) (flags || []).push('Tagged as scam on Blockscout');
  const badge = flags == null ? '<div class="badge b-idle">THREAT DATA UNAVAILABLE</div>'
    : flags.length ? `<div class="badge b-crit">${flags.length} RISK FLAG${flags.length > 1 ? 'S' : ''} ON RECORD</div>`
    : '<div class="badge b-safe">NO RISK FLAGS ON RECORD</div>';
  const eth = info && info.coin_balance != null ? Number(info.coin_balance) / 1e18 : null;
  const kv = [
    ['Address', short(addr)],
    ['Type', info ? (info.is_contract ? 'Contract' : 'Wallet') : '—'],
    ['ETH balance', eth == null ? '—' : amt(eth) + ' ETH'],
    ['Transactions', counters && counters.transactions_count != null ? Number(counters.transactions_count).toLocaleString() : '—'],
    ['Token transfers', counters && counters.token_transfers_count != null ? Number(counters.token_transfers_count).toLocaleString() : '—'],
    ['Blockscout scam tag', info ? (info.is_scam ? 'Yes' : 'No') : '—']];
  $('wfRep').innerHTML = badge
    + `<div class="kv">${kv.map(([k, v]) => `<span>${esc(k)}</span><span>${esc(v)}</span>`).join('')}</div>`
    + (flags && flags.length ? `<ul class="wfflags">${flags.map(f => `<li>${esc(f)}</li>`).join('')}</ul>` : '')
    + `<p class="fine">From public threat-intel databases. A clean record is not a guarantee. <a href="${BS}/address/${esc(addr)}" target="_blank" rel="noopener">View on explorer ↗</a></p>`;
}

/* ---------- scoring one token with the page's own engine ---------- */
function score(pair, raw, pv) {
  const p = pair || {liquidity: {usd: 0}, volume: {}, priceChange: {}, txns: {m5: {}, h1: {}, h6: {}, h24: {buys: 0, sells: 0}}};
  if (typeof window.normalize !== 'function' || typeof window.scoreToken !== 'function')
    throw new Error('scoring engine not available on this page');
  /* official Robinhood Stock Tokens are scored by the engine's issuer path even without GoPlus data */
  if (!raw && !(pv && pv.official)) return {score: null, verdict: 'UNVERIFIED — NO SECURITY DATA', cls: 'b-caut', d: [['No security record from GoPlus', 'unscored']]};
  return window.scoreToken(p, raw ? window.normalize(raw, p) : null, pv || null);
}
/* provenance (official Stock Token check, deployer history) from the page's own engine, if present */
const getProvenance = ca => typeof window.provenance === 'function' ? window.provenance(ca).catch(() => null) : Promise.resolve(null);

/* ---------- main wallet scan ---------- */
async function scanWallet(addr) {
  addr = (addr || '').trim();
  if (!isAddr(addr)) { setStatus('Enter a valid 0x wallet address.', true); return; }
  if (busy) return;
  busy = true; lastScanned = addr.toLowerCase();
  const btn = $('wfBtn'); btn.disabled = true; btn.textContent = 'Scanning…';
  rows = []; $('wfRows').innerHTML = '<p class="fine">Reading holdings…</p>';
  ['wfVal', 'wfN', 'wfSafety', 'wfRisk', 'wfMix'].forEach(id => { $(id).textContent = '—'; $(id).style.color = ''; });
  setStatus('Reading holdings from Blockscout…');
  agentLog(`Wallet: scan requested for ${short(addr)}`, 'inf');
  try {
    const [p1, info, counters, gpAddr] = await Promise.all([
      getJSON(`${BS}/api/v2/addresses/${addr}/tokens?type=ERC-20`, 'Blockscout'),
      getJSON(`${BS}/api/v2/addresses/${addr}`, 'Blockscout').catch(() => null),
      getJSON(`${BS}/api/v2/addresses/${addr}/counters`, 'Blockscout').catch(() => null),
      getJSON(`https://api.gopluslabs.io/api/v1/address_security/${addr}?chain_id=${CHAIN_ID}`, 'GoPlus').then(d => d && d.result || null).catch(() => null)]);
    renderRep(addr, gpAddr, info, counters);

    let items = (p1.items || []).slice();
    if (p1.next_page_params) {
      const qs = new URLSearchParams(Object.entries(p1.next_page_params).filter(([, v]) => v != null)).toString();
      const p2 = await getJSON(`${BS}/api/v2/addresses/${addr}/tokens?type=ERC-20&${qs}`, 'Blockscout').catch(() => null);
      if (p2 && p2.items) items = items.concat(p2.items);
    }
    let list = items.filter(x => x && x.token && x.value && x.value !== '0').map(x => {
      const t = x.token, dec = Number(t.decimals || 18), bal = Number(x.value) / Math.pow(10, dec);
      const rate = t.exchange_rate != null ? Number(t.exchange_rate) : null;
      return {token: {address: t.address_hash, symbol: t.symbol, name: t.name}, bal, val: rate ? bal * rate : null, scam: t.reputation && t.reputation !== 'ok'};
    });
    const totalTokens = list.length;
    agentLog(`Wallet: ${totalTokens} ERC-20 holdings found`, 'ok');

    /* market data, 30 tokens per DexScreener call */
    const best = {};
    for (let i = 0; i < list.length; i += 30) {
      const csv = list.slice(i, i + 30).map(r => r.token.address).join(',');
      const d = await getJSON('https://api.dexscreener.com/latest/dex/tokens/' + csv, 'DexScreener').catch(() => null);
      (d && d.pairs || []).forEach(p => {
        const k = (p.baseToken && p.baseToken.address || '').toLowerCase();
        if (k && (!best[k] || (p.liquidity && p.liquidity.usd || 0) > (best[k].liquidity && best[k].liquidity.usd || 0))) best[k] = p;
      });
    }
    list.forEach(r => { r.pair = best[r.token.address.toLowerCase()] || null;
      if (r.val == null && r.pair && r.pair.priceUsd) r.val = r.bal * Number(r.pair.priceUsd); });
    list.sort((a, b) => (b.val || 0) - (a.val || 0) || (b.scam ? 1 : 0) - (a.scam ? 1 : 0));

    /* scam-tagged tokens are always shown; real holdings are scored; dust is listed only */
    const scam = list.filter(r => r.scam);
    const real = list.filter(r => !r.scam && (r.val || 0) >= DUST_USD);
    const toScore = real.slice(0, MAX_TOKENS);
    const over = real.length - toScore.length;
    const dust = list.filter(r => !r.scam && (r.val || 0) < DUST_USD);
    dust.forEach(r => { r.dust = true; r.res = {score: null, verdict: 'DUST — NOT SCORED', cls: 'b-idle', d: [['Worth under $' + DUST_USD + ', not scored', '']]}; });
    scam.forEach(r => { r.res = {score: 0, verdict: 'SCAM — FLAGGED BY BLOCKSCOUT', cls: 'b-crit', d: [['Flagged as scam token by Blockscout', '→ 0']]}; });

    const eth = info && info.coin_balance != null ? Number(info.coin_balance) / 1e18 : 0;
    rows = [...toScore, ...scam, ...dust.slice(0, 15)];
    if (eth > 0) rows.unshift({native: true, token: {symbol: 'ETH', name: 'Gas token'}, bal: eth,
      val: info.exchange_rate ? eth * Number(info.exchange_rate) : null,
      res: {score: null, verdict: 'NATIVE GAS TOKEN', cls: 'b-idle', d: [['Native gas token, not scored', '']]}});
    const notes = [];
    if (over > 0) notes.push(`${over} more holding${over > 1 ? 's' : ''} above $${DUST_USD} not scored here; use Full ↗ or the scanner above.`);
    if (dust.length) notes.push(`${dust.length} dust holding${dust.length > 1 ? 's' : ''} under $${DUST_USD} (often airdropped spam) listed without a score${dust.length > 15 ? ', first 15 shown' : ''}.`);
    const extra = notes.join(' ');
    $('wfCount').textContent = `${totalTokens} token${totalTokens === 1 ? '' : 's'}`;
    renderRows(extra); renderSummary();

    /* score each real holding with GoPlus + the page's engine */
    let done = 0;
    for (const r of toScore) {
      done++; setStatus(`Scoring ${done} of ${toScore.length}: $${r.token.symbol || '?'}…`);
      r.state = 'Scoring…'; renderRows(extra);
      const pvP = getProvenance(r.token.address);
      try {
        const raw = await goplusToken(r.token.address, s => setStatus(`GoPlus free-tier rate limit reached. Resuming in ${s}s (${done} of ${toScore.length})…`));
        r.res = score(r.pair, raw, await pvP);
      } catch (e) {
        const pv = await pvP;
        r.res = pv && pv.official ? score(r.pair, null, pv)
          : {score: null, verdict: 'UNVERIFIED — SECURITY DATA UNAVAILABLE', cls: 'b-caut', d: [['GoPlus unavailable: ' + e.message, 'unscored']]};
        agentLog(`Wallet: GoPlus unavailable for $${r.token.symbol}: ${e.message}`, 'warn');
      }
      if (r.res && r.res.cls === 'b-crit') agentLog(`Wallet: $${r.token.symbol} → ${r.res.verdict} (${r.res.score}/100)`, 'bad');
      renderRows(extra); renderSummary();
      await sleep(GAP_MS);
    }
    const crit = rows.filter(r => r.res && r.res.cls === 'b-crit').length;
    setStatus(crit ? `Scan complete. ${crit} holding${crit > 1 ? 's' : ''} rated critical risk.` : 'Scan complete. No critical-risk holdings found.', false);
    agentLog(`Wallet: scan complete, ${crit} critical`, crit ? 'bad' : 'ok');
  } catch (e) {
    setStatus('Wallet scan failed: ' + e.message, true);
    agentLog('Wallet: scan failed: ' + e.message, 'bad');
    if (!rows.length) $('wfRows').innerHTML = '<p class="fine">No data. Check the address and try again.</p>';
  } finally {
    busy = false; btn.disabled = false; btn.textContent = 'Scan wallet';
  }
}

/* ---------- mount ---------- */
function mount() {
  if ($('wallet')) return;
  const style = document.createElement('style'); style.textContent = css; document.head.appendChild(style);
  const sec = document.createElement('section'); sec.id = 'wallet'; sec.innerHTML = sectionHTML;
  const desk = $('desk');
  if (desk && desk.parentNode) desk.parentNode.insertBefore(sec, desk.nextSibling); else (document.querySelector('main') || document.body).appendChild(sec);

  /* nav link */
  const nav = document.querySelector('.navlinks');
  if (nav && !nav.querySelector('a[href="#wallet"]')) {
    const a = document.createElement('a'); a.href = '#wallet'; a.textContent = 'Wallet';
    const deskLink = nav.querySelector('a[href="#desk"]');
    deskLink ? deskLink.after(a) : nav.appendChild(a);
  }

  /* sign-in modal: say what connecting does */
  const sp = document.querySelector('#signModal p');
  if (sp && !sp.dataset.wf) { sp.dataset.wf = '1'; sp.textContent += ' Once connected, OMEN scans the wallet’s holdings for risky tokens and checks the address against threat-intel records.'; }

  /* changelog + FAQ */
  const cl = document.querySelector('#changelog .cl');
  if (cl) cl.insertAdjacentHTML('afterbegin', `<li><div class="ver">v0.8.0<small>Nov 2026</small></div><div><b>Wallet Forensics</b><p>Connect a wallet or paste an address: every ERC-20 holding is scored by the same engine, with value-weighted portfolio safety and an address threat-intel check from GoPlus and Blockscout.</p></div></li>`);
  const faq = $('faq');
  if (faq) faq.insertAdjacentHTML('beforeend', `<details><summary>What does connecting a wallet do?</summary><p>OMEN reads the public address only. It lists the wallet’s Robinhood Chain tokens from Blockscout, scores each one with the same engine as the scanner, and checks the address against GoPlus threat-intel. No signature, approval or transaction is ever requested.</p></details>`);

  /* wiring */
  $('wfForm').addEventListener('submit', e => { e.preventDefault(); scanWallet($('wfAddr').value); });
  $('wfUse').addEventListener('click', () => {
    if (connected) { $('wfAddr').value = connected; scanWallet(connected); }
    else { const b = $('openSignin'); if (b) b.click(); }
  });
  $('wfRows').addEventListener('click', e => {
    const b = e.target.closest('.wfgo'); if (!b) return;
    const r = rows[+b.dataset.i]; if (!r || r.native) return;
    const input = $('caInput'), form = $('scanForm');
    if (input && form) { input.value = r.token.address; form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event('submit', {cancelable: true}));
      const dash = $('dashboard'); if (dash) dash.scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'}); }
  });

  /* react to the page's Sign In: it writes "Connected: 0x…" into #signStatus */
  const ss = $('signStatus');
  if (ss) new MutationObserver(() => {
    const m = (ss.textContent || '').match(/0x[a-fA-F0-9]{40}/);
    if (!m || (connected && connected.toLowerCase() === m[0].toLowerCase())) return;
    connected = m[0]; $('wfAddr').value = connected; $('wfUse').textContent = 'Rescan my wallet';
    if (lastScanned !== connected.toLowerCase()) {
      setTimeout(() => { scanWallet(connected); sec.scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'}); }, 1000);
    }
  }).observe(ss, {childList: true, characterData: true, subtree: true});
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount); else mount();
})();
