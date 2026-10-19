const VERSION = '2';
const SLOTS = 3;
const $ = id => document.getElementById(id);
const t0 = performance.now();
let role = null;
let currentPayload = '';
let camStream = null;
let invitation = null;
let guestPeer = null;
const hostPeers = [];

$('ver').textContent = VERSION;
$('ua').textContent = navigator.userAgent.match(/(iPhone OS [\d_]+|Android [\d.]+|Mac OS X [\d_]+|Windows NT [\d.]+)/)?.[0] ?? 'unknown';
const showOnline = () => $('online').textContent = navigator.onLine ? 'online' : 'offline';
showOnline(); addEventListener('online', showOnline); addEventListener('offline', showOnline);

if ('serviceWorker' in navigator) {
  const hadController = !!navigator.serviceWorker.controller;
  navigator.serviceWorker.addEventListener('controllerchange', () => hadController && location.reload());
  navigator.serviceWorker.register('sw.js').then(
    () => navigator.serviceWorker.ready.then(() => $('sw').textContent = 'ready'),
    e => $('sw').textContent = 'fail ' + e.message);
} else $('sw').textContent = 'n/a';

const logLines = JSON.parse(localStorage.getItem('log') || '[]');
function log(msg) {
  const line = `${new Date().toISOString().slice(11, 23)} +${((performance.now() - t0) / 1000).toFixed(2)}s ${msg}`;
  logLines.push(line);
  if (logLines.length > 500) logLines.shift();
  localStorage.setItem('log', JSON.stringify(logLines));
  $('log').textContent = logLines.join('\n');
  $('log').scrollTop = 1e9;
}
$('log').textContent = logLines.join('\n');
log(`page load v${VERSION} ${navigator.userAgent}`);

let audio = null;
function beep() {
  if (!audio) return;
  const o = audio.createOscillator(), g = audio.createGain();
  o.frequency.value = 880; g.gain.value = 0.2;
  o.connect(g).connect(audio.destination);
  o.start(); o.stop(audio.currentTime + 0.15);
}
const toast = (text, cls = '') => { $('toast').textContent = text; $('toast').className = cls; };

// --- payload encoding ---
// Invitation: I|<fingerprint>|<ip,ip>|<ufrag pwd ipIdx.port,ipIdx.port>;<slot 2>;<slot 3>
// Answer:     A|<slot>|<ufrag>|<pwd>|<fingerprint>|<ip/port ip/port>

const b64u = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const fpToB64 = fp => b64u(Uint8Array.from(fp.split(':'), h => parseInt(h, 16)));
const b64ToFp = s => [...unb64u(s)].map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');

function parseSdp(sdp) {
  const get = k => sdp.match(new RegExp(`a=${k}:(.+)`))?.[1].trim();
  const cands = [...sdp.matchAll(/a=candidate:\S+ \d+ (\S+) \d+ (\S+) (\d+) typ (\S+)/g)]
    .filter(m => m[1].toLowerCase() === 'udp' && m[4] === 'host')
    .map(m => ({ ip: m[2], port: m[3] }));
  return { ufrag: get('ice-ufrag'), pwd: get('ice-pwd'), fp: get('fingerprint').split(' ')[1], cands };
}

function buildSdp(type, { ufrag, pwd, fp, cands }) {
  return [
    'v=0', 'o=- 4611731400430051336 2 IN IP4 127.0.0.1', 's=-', 't=0 0',
    'a=group:BUNDLE 0', 'a=msid-semantic: WMS',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel', 'c=IN IP4 0.0.0.0',
    `a=ice-ufrag:${ufrag}`, `a=ice-pwd:${pwd}`, 'a=ice-options:trickle',
    `a=fingerprint:sha-256 ${fp}`, `a=setup:${type === 'offer' ? 'actpass' : 'active'}`,
    'a=mid:0', 'a=sctp-port:5000', 'a=max-message-size:262144',
    ...cands.map((c, i) => `a=candidate:${i + 1} 1 udp ${2122260223 - i} ${c.ip} ${c.port} typ host generation 0`),
    'a=end-of-candidates', '',
  ].join('\r\n');
}

function encodeInvitation(descs) {
  const parsed = descs.map(d => parseSdp(d.sdp));
  const ips = [...new Set(parsed.flatMap(p => p.cands.map(c => c.ip)))];
  const slots = parsed.map(p => `${p.ufrag} ${p.pwd} ${p.cands.map(c => `${ips.indexOf(c.ip)}.${c.port}`).join(',')}`);
  return ['I', fpToB64(parsed[0].fp), ips.join(','), slots.join(';')].join('|');
}

function decodeInvitation(text, slot) {
  const [, fpB64, ipStr, slotStr] = text.split('|');
  const ips = ipStr.split(',');
  const [ufrag, pwd, candStr] = slotStr.split(';')[slot].split(' ');
  const cands = candStr.split(',').filter(Boolean).map(s => { const [i, port] = s.split('.'); return { ip: ips[+i], port }; });
  return { type: 'offer', sdp: buildSdp('offer', { ufrag, pwd, fp: b64ToFp(fpB64), cands }) };
}

function encodeAnswer(slot, desc) {
  const p = parseSdp(desc.sdp);
  return ['A', slot, p.ufrag, p.pwd, fpToB64(p.fp), p.cands.map(c => `${c.ip}/${c.port}`).join(' ')].join('|');
}

function decodeAnswer(text) {
  const [, slot, ufrag, pwd, fpB64, candStr] = text.split('|');
  const cands = candStr.split(' ').filter(Boolean).map(s => { const [ip, port] = s.split('/'); return { ip, port }; });
  return { slot: +slot, desc: { type: 'answer', sdp: buildSdp('answer', { ufrag, pwd, fp: b64ToFp(fpB64), cands }) } };
}

// --- QR display and camera ---

function showQr(text, label) {
  currentPayload = text;
  const qr = qrcode(0, 'L');
  qr.addData(text, 'Byte');
  qr.make();
  const version = (qr.getModuleCount() - 17) / 4;
  $('qr').innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
  $('qrLabel').textContent = `${label} · ${text.length} 字元 · QR 版本 ${version}`;
  $('qrBox').classList.remove('hidden');
  log(`QR shown ${label}: ${text.length} chars, version ${version}`);
}
const hideQr = () => $('qrBox').classList.add('hidden');

async function startCamera(facingMode, videoClass) {
  const t = performance.now();
  camStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode, width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false });
  const s = camStream.getVideoTracks()[0].getSettings();
  log(`camera ${facingMode} granted in ${(performance.now() - t).toFixed(0)}ms, ${s.width}x${s.height}`);
  const video = $('video');
  video.srcObject = camStream;
  video.className = videoClass;
  video.style.transform = facingMode === 'user' ? 'scaleX(-1)' : '';
  await video.play();
}
function stopCamera() {
  camStream?.getTracks().forEach(tr => tr.stop());
  camStream = null;
  $('video').className = 'hidden';
}

// Calls onCode for every newly seen QR text until stop() is called.
function scanLoop(onCode) {
  const video = $('video');
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const seen = new Set();
  let running = true;
  const tick = () => {
    if (!running) return;
    if (video.readyState >= 2) {
      const scale = Math.min(1, 800 / video.videoWidth);
      canvas.width = video.videoWidth * scale; canvas.height = video.videoHeight * scale;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const code = jsQR(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height, { inversionAttempts: 'dontInvert' });
      if (code?.data && !seen.has(code.data)) { seen.add(code.data); onCode(code.data); }
    }
    requestAnimationFrame(tick);
  };
  tick();
  return () => { running = false; };
}

// --- peer connection ---

async function gather(pc, label) {
  const t = performance.now();
  if (pc.iceGatheringState !== 'complete') {
    await new Promise(resolve => {
      pc.addEventListener('icegatheringstatechange', () => pc.iceGatheringState === 'complete' && resolve());
      setTimeout(resolve, 5000);
    });
  }
  const p = parseSdp(pc.localDescription.sdp);
  log(`${label} gathering ${pc.iceGatheringState} in ${(performance.now() - t).toFixed(0)}ms; candidates: ${p.cands.map(c => c.ip).join(', ') || 'NONE'}`);
  if (p.cands.some(c => c.ip.endsWith('.local'))) log('WARNING: mDNS (.local) candidates present');
}

function makePeer(label, certificate, onOpen) {
  const pc = new RTCPeerConnection({ iceServers: [], certificates: certificate ? [certificate] : undefined });
  const peer = { label, pc, dc: null, rtt: null, el: document.createElement('div'), open: false };
  $('seats').appendChild(peer.el);
  peer.render = () => {
    const st = pc.connectionState;
    const state = peer.open ? '已連線' : pc.remoteDescription && role === 'host' ? '連線中' : '等待中';
    peer.el.innerHTML = `<b>${label}</b> · <span class="${peer.open && st === 'connected' ? 'ok' : st === 'failed' || st === 'disconnected' ? 'bad' : ''}">${state} (${st})</span> · RTT ${peer.rtt ?? '-'}ms`;
  };
  pc.addEventListener('iceconnectionstatechange', () => { log(`${label} ice ${pc.iceConnectionState}`); peer.render(); });
  pc.addEventListener('connectionstatechange', () => { log(`${label} connection ${pc.connectionState}`); peer.render(); });
  peer.wire = dc => {
    peer.dc = dc;
    dc.addEventListener('open', () => {
      peer.open = true;
      log(`${label} datachannel open, ${((performance.now() - peer.tRemote) / 1000).toFixed(2)}s after remote description`);
      peer.render();
      onOpen?.(peer);
      setInterval(() => dc.readyState === 'open' && dc.send(JSON.stringify({ ping: performance.now() })), 1000);
    });
    dc.addEventListener('close', () => log(`${label} datachannel close`));
    dc.addEventListener('message', e => {
      const m = JSON.parse(e.data);
      if (m.ping != null) dc.send(JSON.stringify({ pong: m.ping }));
      if (m.pong != null) { peer.rtt = (performance.now() - m.pong).toFixed(0); peer.render(); }
    });
  };
  peer.render();
  return peer;
}

// --- host flow ---

let stopHostScan = null;

$('beHost').onclick = async () => {
  role = 'host';
  audio = new (window.AudioContext || window.webkitAudioContext)();
  const facing = document.querySelector('input[name=cam]:checked').value;
  $('roleBtns').classList.add('hidden');
  log(`role host, camera ${facing}`);
  try {
    try { await startCamera(facing, 'preview'); }
    catch (e) { log('camera failed, paste only: ' + e.message); }
    const certificate = await RTCPeerConnection.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256' });
    for (let i = 0; i < SLOTS; i++) {
      const peer = makePeer(`座位 ${i + 1}`, certificate, onGuestOpen);
      peer.wire(peer.pc.createDataChannel('game'));
      await peer.pc.setLocalDescription(await peer.pc.createOffer());
      hostPeers.push(peer);
    }
    await Promise.all(hostPeers.map(p => gather(p.pc, p.label)));
    showQr(encodeInvitation(hostPeers.map(p => p.pc.localDescription)), '邀請（3 個座位）');
    toast(facing === 'user' ? '請加入者掃描，再把回應螢幕朝下蓋在主機上方' : '請加入者掃描，再翻過來掃他們的回應');
    if (camStream) stopHostScan = scanLoop(text => acceptAnswer(text).catch(e => log('ERROR ' + e.message)));
  } catch (e) { log('ERROR ' + e.message); }
};

async function acceptAnswer(text) {
  if (!text.startsWith('A|')) return log(`ignored QR (not an answer): ${text.slice(0, 20)}`);
  const { slot, desc } = decodeAnswer(text);
  const peer = hostPeers[slot];
  if (!peer) return log(`answer for unknown slot ${slot}`);
  if (peer.pc.remoteDescription) {
    toast(`座位 ${slot + 1} 已經有人了，請對方改選座位`, 'bad');
    return log(`slot ${slot + 1} already taken, answer ignored`);
  }
  peer.tRemote = performance.now();
  await peer.pc.setRemoteDescription(desc);
  log(`${peer.label} answer applied`);
  peer.render();
}

function onGuestOpen(peer) {
  beep();
  const n = hostPeers.filter(p => p.open).length;
  toast(`${peer.label} 已連線（${n}/${SLOTS}）`, 'ok');
  if (n === SLOTS) {
    stopHostScan?.();
    stopCamera();
    hideQr();
    toast('三個座位都連上了', 'ok');
  }
}

// --- guest flow ---

let stopGuestScan = null;

$('beGuest').onclick = async () => {
  role = 'guest';
  $('roleBtns').classList.add('hidden');
  log('role guest');
  toast('掃描主機的邀請 QR code');
  try {
    await startCamera('environment', 'full');
    const t = performance.now();
    stopGuestScan = scanLoop(text => {
      if (!text.startsWith('I|')) return log(`ignored QR (not an invitation): ${text.slice(0, 20)}`);
      log(`scanned invitation ${text.length} chars in ${(performance.now() - t).toFixed(0)}ms`);
      stopGuestScan();
      gotInvitation(text);
    });
  } catch (e) { log('ERROR ' + e.message); }
};

function gotInvitation(text) {
  invitation = text;
  toast('');
  $('slotPick').classList.remove('hidden');
}

document.querySelectorAll('#slotPick button').forEach(b => b.onclick = () => pickSlot(+b.dataset.slot).catch(e => log('ERROR ' + e.message)));

async function pickSlot(slot) {
  $('slotPick').classList.add('hidden');
  if (guestPeer) { guestPeer.pc.close(); guestPeer.el.remove(); }
  const peer = guestPeer = makePeer(`主機（座位 ${slot + 1}）`, null, () => {
    stopCamera(); hideQr(); $('repick').classList.add('hidden');
    toast('已連線，等主機開始', 'ok');
  });
  peer.pc.addEventListener('datachannel', e => peer.wire(e.channel));
  peer.tRemote = performance.now();
  await peer.pc.setRemoteDescription(decodeInvitation(invitation, slot));
  await peer.pc.setLocalDescription(await peer.pc.createAnswer());
  await gather(peer.pc, peer.label);
  showQr(encodeAnswer(slot, peer.pc.localDescription), `座位 ${slot + 1} 的回應`);
  toast('請拿給主機掃描');
  $('repick').classList.remove('hidden');
}

$('repick').onclick = () => { hideQr(); $('repick').classList.add('hidden'); $('slotPick').classList.remove('hidden'); };

// --- manual fallback and log tools ---

$('pasteGo').onclick = async () => {
  const text = $('paste').value.trim();
  try {
    if (role === 'host') await acceptAnswer(text);
    else if (role === 'guest') { stopGuestScan?.(); gotInvitation(text); }
    else log('paste ignored: choose a role first');
  } catch (e) { log('ERROR ' + e.message); }
};
$('copyPayload').onclick = () => navigator.clipboard.writeText(currentPayload).then(() => log('payload copied'));
$('copyLog').onclick = () => navigator.clipboard.writeText(logLines.join('\n')).then(() => log('log copied'));
$('clearLog').onclick = () => { logLines.length = 0; localStorage.setItem('log', '[]'); $('log').textContent = ''; };
