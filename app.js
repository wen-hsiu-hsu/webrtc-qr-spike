const VERSION = '1';
const $ = id => document.getElementById(id);
const t0 = performance.now();
const peers = [];
let role = null;
let currentPayload = '';
let pendingPeer = null;
let camStream = null;
let scanning = false;

$('ver').textContent = VERSION;
$('ua').textContent = navigator.userAgent.match(/(iPhone OS [\d_]+|Android [\d.]+|Mac OS X [\d_]+|Windows NT [\d.]+)/)?.[0] ?? 'unknown';
const showOnline = () => $('online').textContent = navigator.onLine ? 'online' : 'offline';
showOnline(); addEventListener('online', showOnline); addEventListener('offline', showOnline);

if ('serviceWorker' in navigator) {
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

const enc = () => document.querySelector('input[name=enc]:checked').value;

// --- payload encoding ---

const b64u = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

async function deflate(text) {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function inflate(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Response(stream).text();
}

function parseSdp(sdp) {
  const get = k => sdp.match(new RegExp(`a=${k}:(.+)`))?.[1].trim();
  const cands = [...sdp.matchAll(/a=candidate:\S+ \d+ (\S+) \d+ (\S+) (\d+) typ (\S+)/g)]
    .filter(m => m[1].toLowerCase() === 'udp')
    .map(m => ({ ip: m[2], port: m[3], typ: m[4] }));
  return { ufrag: get('ice-ufrag'), pwd: get('ice-pwd'), fp: get('fingerprint').split(' ')[1], cands };
}

function buildSdp(type, { ufrag, pwd, fp, cands }) {
  const lines = [
    'v=0', 'o=- 4611731400430051336 2 IN IP4 127.0.0.1', 's=-', 't=0 0',
    'a=group:BUNDLE 0', 'a=msid-semantic: WMS',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel', 'c=IN IP4 0.0.0.0',
    `a=ice-ufrag:${ufrag}`, `a=ice-pwd:${pwd}`, 'a=ice-options:trickle',
    `a=fingerprint:sha-256 ${fp}`, `a=setup:${type === 'offer' ? 'actpass' : 'active'}`,
    'a=mid:0', 'a=sctp-port:5000', 'a=max-message-size:262144',
    ...cands.map((c, i) => `a=candidate:${i + 1} 1 udp ${2122260223 - i} ${c.ip} ${c.port} typ host generation 0`),
    'a=end-of-candidates',
  ];
  return lines.join('\r\n') + '\r\n';
}

async function encodeDesc(desc) {
  if (enc() === 'F') return 'F' + b64u(await deflate(JSON.stringify({ type: desc.type, sdp: desc.sdp })));
  const p = parseSdp(desc.sdp);
  const fp = b64u(Uint8Array.from(p.fp.split(':'), h => parseInt(h, 16)));
  const cands = p.cands.filter(c => c.typ === 'host').map(c => `${c.ip}/${c.port}`).join(' ');
  return ['M', desc.type === 'offer' ? 'O' : 'A', p.ufrag, p.pwd, fp, cands].join('|');
}

async function decodeDesc(text) {
  if (text[0] === 'F') return JSON.parse(await inflate(unb64u(text.slice(1))));
  const [, t, ufrag, pwd, fpB64, candStr] = text.split('|');
  const fp = [...unb64u(fpB64)].map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
  const cands = candStr.split(' ').filter(Boolean).map(s => { const [ip, port] = s.split('/'); return { ip, port }; });
  const type = t === 'O' ? 'offer' : 'answer';
  return { type, sdp: buildSdp(type, { ufrag, pwd, fp, cands }) };
}

// --- QR display and scan ---

function showQr(text, label) {
  currentPayload = text;
  const qr = qrcode(0, 'L');
  qr.addData(text, 'Byte');
  qr.make();
  $('qr').innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
  $('qrLabel').textContent = `${label} · ${text.length} 字元 · QR 版本 ${(qr.getModuleCount() - 17) / 4}`;
  $('qrBox').classList.remove('hidden');
  log(`QR shown ${label}: ${text.length} chars, version ${(qr.getModuleCount() - 17) / 4}`);
}
const hideQr = () => $('qrBox').classList.add('hidden');

async function ensureCamera() {
  if (camStream) return camStream;
  const t = performance.now();
  camStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  log(`camera granted in ${(performance.now() - t).toFixed(0)}ms`);
  return camStream;
}
function stopCamera() {
  camStream?.getTracks().forEach(tr => tr.stop());
  camStream = null;
  $('video').classList.add('hidden');
}

async function scan() {
  const stream = await ensureCamera();
  const video = $('video');
  video.srcObject = stream;
  video.classList.remove('hidden');
  await video.play();
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const t = performance.now();
  scanning = true;
  return new Promise(resolve => {
    const tick = () => {
      if (!scanning) return;
      if (video.readyState >= 2) {
        canvas.width = video.videoWidth; canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const code = jsQR(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height, { inversionAttempts: 'dontInvert' });
        if (code?.data) {
          scanning = false;
          video.classList.add('hidden');
          log(`scanned ${code.data.length} chars in ${(performance.now() - t).toFixed(0)}ms`);
          return resolve(code.data);
        }
      }
      requestAnimationFrame(tick);
    };
    tick();
  });
}

// --- peer connection ---

async function gather(pc) {
  const t = performance.now();
  if (pc.iceGatheringState !== 'complete') {
    await new Promise(resolve => {
      const done = () => pc.iceGatheringState === 'complete' && resolve();
      pc.addEventListener('icegatheringstatechange', done);
      setTimeout(resolve, 5000);
    });
  }
  const p = parseSdp(pc.localDescription.sdp);
  log(`gathering ${pc.iceGatheringState} in ${(performance.now() - t).toFixed(0)}ms; candidates: ${p.cands.map(c => `${c.typ}:${c.ip}`).join(', ') || 'NONE'}`);
  if (p.cands.some(c => c.ip.endsWith('.local'))) log('WARNING: mDNS (.local) candidates present');
}

function makePeer(label) {
  const pc = new RTCPeerConnection({ iceServers: [] });
  const peer = { label, pc, dc: null, rtt: null, tStart: performance.now(), el: document.createElement('div') };
  $('peers').appendChild(peer.el);
  const render = () => {
    const st = pc.connectionState;
    peer.el.innerHTML = `<b>${label}</b> · <span class="${st === 'connected' ? 'ok' : st === 'failed' ? 'bad' : ''}">${st}</span> · ICE ${pc.iceConnectionState} · RTT ${peer.rtt ?? '-'}ms · ${peer.pair ?? ''}`;
  };
  peer.render = render;
  pc.addEventListener('iceconnectionstatechange', () => { log(`${label} ice ${pc.iceConnectionState}`); render(); });
  pc.addEventListener('connectionstatechange', async () => {
    log(`${label} connection ${pc.connectionState}`);
    if (pc.connectionState === 'connected') {
      const stats = await pc.getStats();
      stats.forEach(s => {
        if (s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded') {
          const l = stats.get(s.localCandidateId), r = stats.get(s.remoteCandidateId);
          peer.pair = `${l?.address ?? l?.ip}:${l?.port} ⇄ ${r?.address ?? r?.ip}:${r?.port}`;
          log(`${label} selected pair ${peer.pair}`);
        }
      });
    }
    render();
  });
  render();
  peers.push(peer);
  return peer;
}

function wireChannel(peer, dc) {
  peer.dc = dc;
  dc.addEventListener('open', () => {
    log(`${peer.label} datachannel open, ${((performance.now() - peer.tRemote) / 1000).toFixed(2)}s after remote description`);
    stopCamera();
    setInterval(() => dc.readyState === 'open' && dc.send(JSON.stringify({ ping: performance.now() })), 1000);
  });
  dc.addEventListener('close', () => log(`${peer.label} datachannel close`));
  dc.addEventListener('message', e => {
    const m = JSON.parse(e.data);
    if (m.ping != null) dc.send(JSON.stringify({ pong: m.ping }));
    if (m.pong != null) { peer.rtt = (performance.now() - m.pong).toFixed(0); peer.render(); }
  });
}

// --- host flow ---

$('beHost').onclick = () => { role = 'host'; $('roleBtns').classList.add('hidden'); $('hostUi').classList.remove('hidden'); log('role host'); };
$('beGuest').onclick = () => { role = 'guest'; $('roleBtns').classList.add('hidden'); $('guestUi').classList.remove('hidden'); log('role guest'); };

$('newPeer').onclick = async () => {
  try {
    if ($('camFirst').checked) await ensureCamera();
    const peer = makePeer(`玩家 ${peers.length + 1}`);
    wireChannel(peer, peer.pc.createDataChannel('game'));
    await peer.pc.setLocalDescription(await peer.pc.createOffer());
    await gather(peer.pc);
    showQr(await encodeDesc(peer.pc.localDescription), `${peer.label} 的邀請`);
    pendingPeer = peer;
    $('scanAnswer').disabled = false;
  } catch (e) { log('ERROR ' + e.message); }
};

async function acceptAnswer(text) {
  const peer = pendingPeer;
  peer.tRemote = performance.now();
  await peer.pc.setRemoteDescription(await decodeDesc(text));
  log(`${peer.label} answer applied`);
  pendingPeer = null;
  $('scanAnswer').disabled = true;
  hideQr();
}

$('scanAnswer').onclick = async () => {
  try { hideQr(); await acceptAnswer(await scan()); } catch (e) { log('ERROR ' + e.message); }
};

// --- guest flow ---

async function acceptOffer(text) {
  const peer = makePeer('主機');
  peer.pc.addEventListener('datachannel', e => wireChannel(peer, e.channel));
  peer.tRemote = performance.now();
  await peer.pc.setRemoteDescription(await decodeDesc(text));
  if (!$('camFirst').checked) stopCamera();
  await peer.pc.setLocalDescription(await peer.pc.createAnswer());
  await gather(peer.pc);
  showQr(await encodeDesc(peer.pc.localDescription), '我的回應，請主機掃描');
}

$('scanOffer').onclick = async () => {
  try { await acceptOffer(await scan()); } catch (e) { log('ERROR ' + e.message); }
};

// --- manual fallback and log tools ---

$('pasteGo').onclick = async () => {
  const text = $('paste').value.trim();
  try {
    if (role === 'host' && pendingPeer) await acceptAnswer(text);
    else if (role === 'guest') await acceptOffer(text);
    else log('paste ignored: choose a role / invite first');
  } catch (e) { log('ERROR ' + e.message); }
};
$('copyPayload').onclick = () => navigator.clipboard.writeText(currentPayload).then(() => log('payload copied'));
$('copyLog').onclick = () => navigator.clipboard.writeText(logLines.join('\n')).then(() => log('log copied'));
$('clearLog').onclick = () => { logLines.length = 0; localStorage.setItem('log', '[]'); $('log').textContent = ''; };
