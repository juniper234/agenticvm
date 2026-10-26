'use strict';
(() => {
  const el = id => document.getElementById(id);
  let view = 'display';
  let observed = {};
  function showView(next) {
    if (!['display', 'tools', 'settings'].includes(next)) return;
    view = next;
    document.documentElement.dataset.view = next;
    document.querySelectorAll('[data-page]').forEach(panel => { panel.hidden = panel.dataset.page !== next; });
    document.querySelectorAll('.nav-item[data-view]').forEach(button => {
      const selected = button.dataset.view === next;
      button.classList.toggle('active', selected);
      if (selected) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    });
    if (next === 'tools') el('controls').open = true;
    if (next === 'settings') el('settings').open = true;
    if (next === 'display') frame();
    window.scrollTo({top: 0, behavior: 'instant'});
  }
  function update(state) {
    if (state) observed = state;
    const android = activeProfile === 'android';
    const windows = activeProfile === 'windows';
    const name = activeOS ? (globalThis.AgenticSettings?.name(activeOS) || 'Custom OS') : windows ? 'Windows' : android ? 'Android' : 'Linux';
    el('breadcrumb-machine').textContent = name;
    el('empty-machine-name').textContent = name;
    el('empty-os-icon').src = windows ? '/icons/panels-top-left.svg' : android ? '/icons/smartphone.svg' : '/icons/monitor.svg';
    const current = running && observed.profile === activeProfile;
    const network = current ? observed.network === 'nat' : el('network').checked;
    const persistent = current ? (windows || (android ? observed.persistent : !!observed.workspace_disk)) : el('persistent').checked;
    el('network-label').textContent = network ? 'Internet on' : 'Offline';
    el('network-icon').src = network ? '/icons/wifi.svg' : '/icons/wifi-off.svg';
    el('storage-label').textContent = persistent ? 'Saved' : 'Temporary';
    const cpus = current ? observed.cpus || (windows ? 2 : 1) : Number(el('cpus').value) || 1;
    el('cpu-label').textContent = cpus + (cpus === 1 ? ' CPU' : ' CPUs');
    const memory = Number(current ? observed.memory_mib : el('memory').value);
    el('ram-label').textContent = memory >= 1024 ? (memory / 1024) + ' GB' : memory + ' MB';
    el('tools-stopped').hidden = ready;
    const starting = document.documentElement.dataset.vmState === 'starting';
    el('tools-stopped').textContent = starting ? 'Tools are ready after startup.' : 'Start the machine first.';
    el('start').querySelector('span').textContent = starting ? 'Starting…' : 'Start';
    document.querySelectorAll('[data-requires-guest]').forEach(button => { button.disabled = !ready || busyCount > 0; });
    if (activeOS) for (const id of ['run-command','download','upload-file']) el(id).disabled = true;
    const urlButton = el('url-form').querySelector('button');
    if (urlButton && activeOS) urlButton.disabled = true;
    document.querySelectorAll('[data-profile]').forEach(button => {
      const selected = button.dataset.profile === activeProfile;
      button.classList.toggle('selected', selected);
      button.setAttribute('aria-pressed', String(selected));
      button.disabled = !selected && (running || busyCount > 0);
    });
  }
  document.querySelectorAll('.nav-item[data-view]').forEach(button => { button.onclick = () => showView(button.dataset.view); });
  document.querySelector('.brand').onclick = event => { event.preventDefault(); showView('display'); };
  document.querySelectorAll('[data-go]').forEach(button => { button.onclick = () => showView(button.dataset.go); });
  document.querySelectorAll('[data-profile]').forEach(button => { button.onclick = () => {
    if (globalThis.AgenticSettings?.available(button.dataset.profile) === false) { showView('settings'); message('Add your Windows ISO or disk in the OS library.'); return; }
    if (button.dataset.profile === activeProfile) { showView('display'); return; }
    if (running || busyCount > 0) { message('Stop the current machine before switching.', true); return; }
    el('profile').value = button.dataset.profile;
    el('profile').dispatchEvent(new Event('change', {bubbles:true}));
    displayState({status:'stopped'});
    showView('display');
  }; });
  for (const id of ['memory', 'network', 'persistent', 'cpus']) el(id).addEventListener('change', () => update());
  el('open-appearance').onclick = () => { showView('settings'); el('reduce-transparency').focus(); };
  el('reduce-transparency').checked = localStorage.getItem('agenticvm-solid') === 'true';
  document.documentElement.dataset.transparency = el('reduce-transparency').checked ? 'reduced' : 'glass';
  el('reduce-transparency').onchange = () => { document.documentElement.dataset.transparency = el('reduce-transparency').checked ? 'reduced' : 'glass'; localStorage.setItem('agenticvm-solid', String(el('reduce-transparency').checked)); };
  el('panel-opacity').oninput = () => {
    const value = Number(el('panel-opacity').value);
    document.documentElement.style.setProperty('--surface-alpha', String(value / 100));
    el('opacity-value').textContent = value + '%';
    localStorage.setItem('agenticvm-opacity', String(value));
  };
  const savedOpacity = Number(localStorage.getItem('agenticvm-opacity'));
  if (savedOpacity >= 2 && savedOpacity <= 18) { el('panel-opacity').value = String(savedOpacity); el('panel-opacity').oninput(); }
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && view !== 'display') showView('display');
  });
  globalThis.AgenticUI = {update, showView};
  update();
})();
