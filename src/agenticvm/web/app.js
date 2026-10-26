'use strict';
const $ = (id) => document.getElementById(id);
const fragment = new URLSearchParams(location.hash.slice(1));
const token = fragment.get('token') || sessionStorage.getItem('agenticvm-token') || '';
if (token) sessionStorage.setItem('agenticvm-token', token);
if (location.hash) history.replaceState(null, '', location.pathname);
let running = false, ready = false, paused = false, framePending = false, statusPending = false;
let busyCount = 0, operationQueue = Promise.resolve(), imageURL = null, lastMove = 0, lastStatus = 0;
let actionMessageTimer;
let settingsInitialized = false;
const editedSettings = new Set();
for (const id of ['memory', 'network', 'persistent', 'profile']) $(id).addEventListener('change', () => editedSettings.add(id));
let activeProfile = 'desktop', activeOS = null, touchStart = null;
function configureProfile(profile, resetChoices = false) {
  activeOS = profile.startsWith('custom:') ? profile.slice(7) : null;
  activeProfile = activeOS ? 'custom' : ['android', 'windows'].includes(profile) ? profile : 'desktop';
  const android = activeProfile === 'android';
  const windows = activeProfile === 'windows';
  const name = activeOS ? (globalThis.AgenticSettings?.name(activeOS) || 'Custom OS') : windows ? 'Windows' : android ? 'Android' : 'Linux';
  $('profile').value = activeOS ? 'custom:' + activeOS : activeProfile;
  const minimum = android ? 2560 : windows ? 2048 : activeOS ? 512 : 768;
  const sizes = [512,768,1024,1536,2048,2560,3072,4096,6144,8192,12288,16384].filter(value => value >= minimum && value <= (android ? 8192 : 16384)).map(value => [value, value + ' MiB']);
  const previous = $('memory').value;
  $('memory').min = String(minimum); $('memory').max = String(android ? 8192 : 16384);
  $('memory').value = !resetChoices && Number(previous) >= minimum && Number(previous) <= Number($('memory').max) ? previous : String(minimum);
  if (resetChoices) { $('network').checked = !android && !windows; $('persistent').checked = true; }
  $('persistent').disabled = windows;
  $('custom-settings').hidden = !activeOS;
  $('display-size').disabled = android;
  if (resetChoices) { $('cpus').value = windows ? '2' : '1'; $('display-size').value = android ? '720x1280' : '1024x768'; }
  $('work-title').textContent = name;
  document.title = name + ' · AgenticVM';
  $('screen').alt = android ? 'Android display. Tap or drag to control.' : 'Linux desktop. Click to control the mouse and keyboard.';
  $('guest-label').textContent = activeOS ? 'Your OS · x86-64' : windows ? 'Server 2025 · Evaluation' : android ? 'Android 15' : 'Debian 13';
  $('display-spec').textContent = (android ? '720 x 1280' : '1024 x 768') + ' / 1 frame per sec';
  $('screen-readout').textContent = 'Press Start to open ' + name + '.';
  $('resolution').textContent = android ? 'Tap or drag to control Android' : 'Click the desktop to use it';
  $('profile-hint').textContent = windows ? 'Windows keeps its disk. Changes apply at the next start.' : android ? 'Android 15. No Play Store.' : 'Changes apply at the next start.';
  $('terminal-command').placeholder = windows ? 'Get-ComputerInfo' : 'uname -a';
  if (resetChoices || ['/workspace/', 'C:/workspace/'].includes($('file-path').value)) $('file-path').value = windows ? 'C:/workspace/' : '/workspace/';
  $('screen').alt = name + ' display. Select to control.';
  $('android-apk').hidden = !android;
  for (const button of document.querySelectorAll('.android-only')) button.hidden = !android;
  for (const button of document.querySelectorAll('[data-key*="+"]')) button.hidden = android;
  globalThis.AgenticUI?.update();
}
$('profile').onchange = () => {
  for (const id of ['profile', 'memory', 'network', 'persistent']) editedSettings.add(id);
  configureProfile($('profile').value, true);
  globalThis.AgenticSettings?.populate();
};

function message(value, error = false) {
  clearTimeout(actionMessageTimer);
  $('message').textContent = value;
  $('message').classList.toggle('error', error);
  $('message').hidden = !value;
  if (value && !error) actionMessageTimer = setTimeout(() => { $('message').hidden = true; }, 6000);
}
async function request(path, data) {
  const options = {headers: {'X-AgenticVM-Token': token}, cache: 'no-store'};
  if (data) { options.method = 'POST'; options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(data); }
  const response = await fetch(path, options);
  if (response.headers.get('Content-Type')?.includes('application/json')) {
    const result = await response.json();
    if (!response.ok || !result.ok) {
      const error = new Error(result.error?.message || 'The desktop action could not complete.');
      error.code = result.error?.code;
      throw error;
    }
    return result.result;
  }
  if (!response.ok) throw new Error('Cannot connect to the local desktop.');
  return response;
}
function busy(value) {
  busyCount += value ? 1 : -1;
  for (const id of ['start', 'stop', 'reset', 'run-command', 'send-text', 'download']) $(id).disabled = busyCount > 0;
  $('apk-file').disabled = busyCount > 0 || !ready;
  $('screen-stage').classList.toggle('working', busyCount > 0);
  globalThis.AgenticUI?.update();
}
function enqueueDesktopOperation(operation) {
  busy(true);
  const work = operationQueue.catch(() => {}).then(async () => {
    while (framePending || statusPending) await new Promise((resolve) => setTimeout(resolve, 50));
    return operation();
  });
  operationQueue = work;
  return work.finally(() => { busy(false); if (!busyCount) { status(); frame(); } });
}
async function requestWhenAvailable(path, data) {
  try { return await request(path, data); }
  catch (error) {
    // The server rejects busy requests before dispatch. Only that response is
    // safe to retry; never repeat successful input or a failed transfer body.
    if (error.code !== 'busy') throw error;
    await new Promise((resolve) => setTimeout(resolve, 350));
    return request(path, data);
  }
}
function action(data, success, quiet = false) {
  return enqueueDesktopOperation(async () => {
    try {
      const result = await requestWhenAvailable('/api/action', data);
      if (success) message(success);
      return result;
    } catch (error) { if (!quiet) message(error.message, true); throw error; }
  });
}
function displayState(state = {}) {
  // Initialize a new tab from the saved session once. Edits made while the
  // first status request was pending remain the user's next-start choices.
  if (!settingsInitialized && state.settings) {
    if (!editedSettings.has('profile')) configureProfile(state.profile === 'custom' ? 'custom:' + state.os_id : state.profile || 'desktop');
    if (!editedSettings.has('memory')) $('memory').value = String(state.settings.memory);
    if (!editedSettings.has('network')) $('network').checked = state.settings.network;
    if (!editedSettings.has('persistent')) $('persistent').checked = state.settings.persistent;
    if (!editedSettings.has('cpus')) $('cpus').value = String(state.settings.cpus || (state.profile === 'windows' ? 2 : 1));
    if (!editedSettings.has('display-size')) $('display-size').value = (state.settings.width || 1024) + 'x' + (state.settings.height || 768);
    settingsInitialized = true;
  }
  running = ['running', 'paused'].includes(state.status) && state.registered !== false;
  ready = running && (state.screen_ready === true || (state.guest_ready === true && state.desktop_ready !== false));
  $('profile').disabled = running || busyCount > 0;
  $('apk-file').disabled = !ready || busyCount > 0;
  const starting = state.status === 'starting' || (running && !ready);
  document.documentElement.dataset.vmState = ready ? 'running' : starting ? 'starting' : 'stopped';
  $('status-label').textContent = ready ? 'Running' : starting ? 'Starting' : 'Stopped';
  $('stage-signal').textContent = ready ? 'Connected' : starting ? 'Connecting' : 'Not connected';
  const os = activeProfile === 'custom' ? (globalThis.AgenticSettings?.name(activeOS) || 'Custom OS') : activeProfile === 'windows' ? 'Windows' : activeProfile === 'android' ? 'Android' : 'Linux';
  $('status-detail').textContent = starting ? 'Starting ' + os + '…' : 'Start ' + os + ' to use the display.';
  $('status-detail').hidden = ready;
  const selectedMemory = Number($('memory').value) || (activeProfile === 'android' ? 2560 : 768);
  const memory = running && (!state.profile || state.profile === activeProfile) ? state.memory_mib || state.memory || selectedMemory : selectedMemory;
  $('ram-label').textContent = memory + ' MiB';
  $('start').hidden = running;
  $('stop').hidden = !running;
  $('reset').disabled = !running || busyCount > 0;
  $('empty-description').textContent = starting ? 'Starting…' : 'Stopped';
  $('screen-readout').textContent = starting ? 'Opening the display…' : 'Press Start to open ' + os + '.';
  if (!running) {
    $('screen').hidden = true; $('empty-screen').hidden = false;
    $('live-label').textContent = starting ? 'Starting' : 'Stopped';
  }
  if (state.startup_error) message(state.startup_error.message, true);
  globalThis.AgenticUI?.update(state);
  globalThis.AgenticSettings?.update();
}
async function status() {
  if (statusPending || busyCount || document.hidden || !token) return;
  statusPending = true;
  try { const state = await request('/api/status'); displayState(state); lastStatus = Date.now(); }
  catch (error) {
    if (error.code === 'busy') { /* Keep the last known state while another request owns the controller. */ }
    else if (['session_missing', 'session_not_found', 'missing_state', 'not_found', 'no_session'].includes(error.code)) displayState();
    else { displayState(); message(error.message, true); }
  } finally { statusPending = false; }
}
async function frame() {
  if (framePending || paused || document.hidden || (document.documentElement.dataset.view && document.documentElement.dataset.view !== 'display') || busyCount || !running || !token) return;
  framePending = true;
  try {
    const response = await request('/api/screen');
    const next = URL.createObjectURL(await response.blob());
    const image = $('screen');
    await new Promise((resolve, reject) => {
      image.onload = resolve; image.onerror = reject; image.src = next;
    });
    if (!running || paused) {
      URL.revokeObjectURL(next);
      image.hidden = true; $('empty-screen').hidden = false;
      return;
    }
    if (imageURL) URL.revokeObjectURL(imageURL);
    imageURL = next; image.hidden = false; $('empty-screen').hidden = true;
    $('resolution').textContent = image.naturalWidth + ' × ' + image.naturalHeight;
    $('live-label').textContent = paused ? 'Paused' : 'Live · 1 frame / sec';
    $('screen-notice').hidden = true;
  } catch (error) {
    if (error.code !== 'busy' && running && !$('screen').hidden) {
      $('screen-notice').textContent = 'Reconnecting to desktop…'; $('screen-notice').hidden = false;
    }
  } finally { framePending = false; }
}
function point(event) {
  const image = $('screen'), rect = image.getBoundingClientRect();
  return {x: Math.min(image.naturalWidth - 1, Math.max(0, Math.floor((event.clientX - rect.left) * image.naturalWidth / rect.width))),
          y: Math.min(image.naturalHeight - 1, Math.max(0, Math.floor((event.clientY - rect.top) * image.naturalHeight / rect.height)))};
}
function start() {
  paused = false;
  $('pause').textContent = 'Pause';
  $('pause').setAttribute('aria-pressed', 'false');
  $('pause').setAttribute('aria-label', 'Pause live view');
  displayState({status: 'starting'});
  const [width,height] = $('display-size').value.split('x').map(Number);
  action({action: 'start', profile: activeProfile, os_id: activeOS, memory: Number($('memory').value), cpus: Number($('cpus').value), width, height, network: $('network').checked, persistent: $('persistent').checked,
    ...(activeOS ? {disk_gib:Number($('disk-gib').value),firmware:$('firmware').value,boot:$('boot-device').value,disk_bus:$('disk-bus').value} : {})}).catch(() => {});
}
$('start').onclick = start;
$('stop').onclick = () => action({action: 'stop'}, 'Desktop stopped.').catch(() => {});
$('reset').onclick = () => {
  if (confirm('Restart this guest? Running apps will close. Unsaved changes and temporary files may be lost.')) action({action: 'reset'}, 'Guest restarted.').catch(() => {});
};
$('pause').onclick = () => {
  paused = !paused; $('pause').textContent = paused ? 'Resume' : 'Pause';
  $('pause').setAttribute('aria-label', paused ? 'Resume live view' : 'Pause live view');
  $('pause').setAttribute('aria-pressed', String(paused));
  $('live-label').textContent = paused ? 'Paused' : 'Live · 1 frame / sec';
  if (!paused) frame();
};
$('refresh').onclick = () => { status(); frame(); };
$('fullscreen').onclick = () => { if (document.fullscreenElement) document.exitFullscreen(); else $('screen-stage').requestFullscreen().catch(() => {}); };
for (const button of document.querySelectorAll('[data-key]')) button.onclick = () => action({action: 'key', keys: button.dataset.key}).catch(() => {});
$('send-text').onclick = () => { if ($('type-text').value) action({action: 'type', text: $('type-text').value}, 'Text sent to guest.').catch(() => {}); };
$('url-form').onsubmit = (event) => {
  event.preventDefault(); let url = $('url').value.trim(); if (!url) return;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) url = 'https://' + url;
  $('url').value = url; action({action: 'open-url', url}, 'Opened in the guest browser.').catch(() => {});
};
$('screen').oncontextmenu = (event) => event.preventDefault();
$('screen').ondragstart = (event) => event.preventDefault();
$('screen').onpointerdown = (event) => {
  event.preventDefault(); $('screen').focus({preventScroll: true});
  if (activeProfile === 'android') { touchStart = point(event); $('screen').setPointerCapture(event.pointerId); return; }
  action({action: 'click', ...point(event), button: ['left', 'middle', 'right'][event.button] || 'left'}).catch(() => {});
};
$('screen').onpointerup = (event) => {
  if (activeProfile !== 'android' || !touchStart) return;
  const start = touchStart, end = point(event); touchStart = null;
  if (Math.hypot(end.x - start.x, end.y - start.y) < 12) action({action: 'click', ...end, button: 'left'}).catch(() => {});
  else action({action: 'swipe', x1: start.x, y1: start.y, x2: end.x, y2: end.y}).catch(() => {});
};
$('screen').onpointercancel = () => { touchStart = null; };
$('screen').onpointermove = (event) => {
  if (activeProfile === 'android') return;
  if (document.activeElement !== $('screen') || busyCount || framePending || Date.now() - lastMove < 220) return;
  lastMove = Date.now(); action({action: 'move', ...point(event)}, null, true).catch(() => {});
};
$('screen').onwheel = (event) => {
  event.preventDefault(); if (busyCount) return;
  action({action: 'scroll', steps: event.deltaY > 0 ? 3 : -3}).catch(() => {});
};
$('screen').addEventListener('wheel', (event) => event.preventDefault(), {passive: false});
$('screen').onkeydown = (event) => {
  if (event.isComposing || ['Shift', 'Control', 'Alt', 'Meta', 'Dead'].includes(event.key)) return;
  event.preventDefault();
  if (event.key.length === 1 && !event.ctrlKey && !event.altKey && !event.metaKey) action({action: 'type', text: event.key}).catch(() => {});
  else {
    const keys = []; if (event.ctrlKey) keys.push('ctrl'); if (event.altKey) keys.push('alt'); if (event.shiftKey) keys.push('shift'); if (event.metaKey) keys.push('meta');
    keys.push(event.key.toLowerCase()); action({action: 'key', keys: keys.join('+')}).catch(() => {});
  }
};
$('run-command').onclick = async () => {
  if (!$('terminal-command').value.trim()) return;
  $('terminal-output').textContent = 'Running in guest…';
  try { const result = await action({action: 'exec', command: $('terminal-command').value});
    $('terminal-output').textContent = (result.stdout || '') + (result.stderr ? '\n' + result.stderr : '') + '\n[exit ' + result.exit_code + ']';
  } catch (error) { $('terminal-output').textContent = error.message; }
};
$('terminal-command').onkeydown = (event) => { if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) { event.preventDefault(); $('run-command').click(); } };
$('upload-file').onchange = async () => {
  const file = $('upload-file').files[0]; if (!file) return;
  try {
    if (file.size > 1024 * 1024) throw new Error('Choose a file no larger than 1 MB.');
    let path = $('file-path').value.trim() || '/workspace/'; if (path.endsWith('/')) path += file.name;
    const bytes = new Uint8Array(await file.arrayBuffer()); let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    await action({action: 'upload', path, data_b64: btoa(binary)}, 'Uploaded ' + file.name + ' to guest.');
    $('file-path').value = path;
  } catch (error) { message(error.message, true); } finally { $('upload-file').value = ''; }
};
$('download').onclick = async () => {
  const path = $('file-path').value.trim(); if (!path || path.endsWith('/')) { message('Enter the full guest file path to download.', true); return; }
  try {
    await enqueueDesktopOperation(async () => {
      const response = await requestWhenAvailable('/api/download?path=' + encodeURIComponent(path));
      const href = URL.createObjectURL(await response.blob()), link = document.createElement('a');
      link.href = href; link.download = path.split('/').pop() || 'download'; link.click();
      setTimeout(() => URL.revokeObjectURL(href), 1000);
      message('Download started.');
    });
  } catch (error) { message(error.message, true); }
};
document.addEventListener('visibilitychange', () => { if (!document.hidden) { status(); frame(); } });
function apkErrorMessage(error = {}) {
  if (error.code !== 'android_command_failed') return error.message || 'APK installation failed.';
  const detail = String(error.message || '');
  if (detail.includes('INSTALL_FAILED_NO_MATCHING_ABIS')) return 'This APK uses an unsupported processor. Choose an APK that supports Android x86-64.';
  if (detail.includes('INSTALL_FAILED_UPDATE_INCOMPATIBLE')) return 'An app with a different signing key is already installed. Choose an update signed by the same publisher.';
  if (detail.includes('INSTALL_FAILED_VERSION_DOWNGRADE')) return 'A newer version of this app is already installed. Choose the same or a newer version.';
  if (detail.includes('INSTALL_FAILED_INSUFFICIENT_STORAGE')) return 'Android has insufficient storage to install this app.';
  if (/Failed to parse|INSTALL_PARSE_FAILED|INVALID_APK/.test(detail)) return 'Android could not read this APK. Choose a valid, complete APK file.';
  return 'Android could not install this APK. Check that it supports Android 15 and x86-64.';
}
$('apk-file').onchange = async () => {
  const file = $('apk-file').files[0]; if (!file) return;
  try {
    if (!file.name.toLowerCase().endsWith('.apk') || file.size > 512 * 1024 * 1024) throw new Error('Choose an APK no larger than 512 MiB.');
    await enqueueDesktopOperation(async () => {
      message('Installing Android app\u2026');
      const response = await fetch('/api/apk', {method: 'POST', headers: {'X-AgenticVM-Token': token, 'Content-Type': 'application/vnd.android.package-archive'}, body: file});
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(apkErrorMessage(result.error));
      message('Android app installed.');
    });
  } catch (error) { message(error.message, true); } finally { $('apk-file').value = ''; }
};
if (!token) { $('status-label').textContent = 'Launch link needed'; $('status-detail').hidden = true; $('empty-description').textContent = 'Open Start-AgenticVM on your computer.'; message('Open this page using the private link from Start-AgenticVM.', true); }
else { status(); setInterval(() => { if (Date.now() - lastStatus >= 3000) status(); frame(); }, 1000); }
