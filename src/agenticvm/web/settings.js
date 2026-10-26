'use strict';
(() => {
  let snapshot = null, pending = false;
  const key = () => activeOS ? 'custom:' + activeOS : activeProfile;
  const editable = ['cpus','display-size','disk-gib','firmware','boot-device','disk-bus'];
  for (const id of editable) $(id).addEventListener('change', () => { editedSettings.add(id); $('save-state').textContent = 'Unsaved changes'; });
  for (const id of ['memory','network','persistent']) $(id).addEventListener('change', () => { $('save-state').textContent = 'Unsaved changes'; });
  function name(id) { return snapshot?.oses[id]?.name || 'Custom OS'; }
  function populate() {
    const values = snapshot?.machines[key()];
    if (values) {
      $('memory').value = String(values.memory); $('cpus').value = String(values.cpus);
      $('network').checked = values.network; $('persistent').checked = values.persistent;
      $('display-size').value = values.width + 'x' + values.height;
      if (activeOS) {
        $('disk-gib').value = String(values.disk_gib); $('firmware').value = values.firmware;
        $('boot-device').value = values.boot; $('disk-bus').value = values.disk_bus;
      }
    }
    $('save-state').textContent = 'Saved settings apply on the next start.';
    globalThis.AgenticUI?.update();
  }
  function update() {
    for (const id of ['save-settings','add-os','reload-settings']) $(id).disabled = running || busyCount > 0 || pending;
    for (const id of ['memory','cpus','network','persistent','display-size','disk-gib','firmware','boot-device','disk-bus']) {
      $(id).disabled = running || busyCount > 0 || pending || (id === 'persistent' && activeProfile === 'windows') || (id === 'display-size' && activeProfile === 'android');
    }
  }
  async function refresh() {
    snapshot = await request('/api/config');
    const selection = activeOS ? 'custom:' + activeOS : activeProfile;
    const builtins = [['Linux · Debian 13','desktop'],['Android 15','android'],[snapshot.available.windows ? 'Windows · prepared local installation' : 'Windows · add your own media','windows']];
    $('profile').replaceChildren(...builtins.map(([label,value]) => new Option(label,value)),
      ...Object.entries(snapshot.oses).map(([id,os]) => new Option(os.name, 'custom:' + id)));
    $('profile').value = selection;
    for (const option of $('profile').options) if (option.value === 'windows') option.disabled = !snapshot.available.windows;
    $('os-media').replaceChildren(...(snapshot.incoming.length ? snapshot.incoming.map(file => new Option(file,file)) : [new Option('No staged media','')]));
    $('media-folder').textContent = snapshot.incoming_folder;
    $('cpus').max = String(snapshot.limits.cpus_max);
    $('os-library').textContent = Object.entries(snapshot.oses).map(([id,os]) => os.name + ' · ' + id).join('\n') || 'No custom OSes yet.';
    const root = snapshot.bridge.launcher.replace(/[\\/]agenticvm-desktop-mcp\.cmd$/, '').replaceAll('\\','/');
    $('bridge-config').value = JSON.stringify({mcpServers:{'agenticvm-desktop':{command:root+'/tools/python-runtime/3.13.16/python.exe',args:['-I','-B','-m','agenticvm.desktop_mcp']}}},null,2);
    $('bridge-state').textContent = 'Connected locally · CLI + 41 MCP tools · no API key';
    if (activeOS) $('work-title').textContent = name(activeOS);
    return snapshot;
  }
  async function operation(work) {
    if (running || busyCount || pending) return;
    pending = true; update();
    try { await work(); }
    catch (error) { $('save-state').textContent = error.message; message(error.message,true); }
    finally { pending = false; update(); }
  }
  $('refresh-media').onclick = () => operation(async () => { await refresh(); message('Media refreshed.'); });
  $('reload-settings').onclick = () => operation(async () => { await refresh(); populate(); });
  $('save-settings').onclick = () => operation(async () => {
    if (!snapshot) await refresh();
    const [width,height] = $('display-size').value.split('x').map(Number);
    const settings = {memory:Number($('memory').value),cpus:Number($('cpus').value),width,height,
      network:$('network').checked,persistent:$('persistent').checked,
      ...(activeOS ? {disk_gib:Number($('disk-gib').value),firmware:$('firmware').value,boot:$('boot-device').value,disk_bus:$('disk-bus').value} : {})};
    snapshot = await request('/api/config',{operation:'save',profile:activeProfile,os_id:activeOS,settings,revision:snapshot.revision});
    $('save-state').textContent = 'Settings saved. Applies on the next start.';
    message('Settings saved.');
  });
  $('add-os').onclick = () => operation(async () => {
    if (!snapshot) await refresh();
    $('save-state').textContent = 'Copying and checking media… Keep this window open.';
    const result = await request('/api/config',{operation:'add_os',name:$('os-name').value,filename:$('os-media').value,revision:snapshot.revision});
    await refresh(); configureProfile('custom:' + result.os_id, true); populate();
    for (const id of ['profile','memory','network','persistent',...editable]) editedSettings.add(id);
    $('save-state').textContent = 'OS added. Review settings, then press Start.';
    message('OS added.');
  });
  globalThis.AgenticSettings = {name,populate,update,refresh,available:profile => snapshot?.available[profile] !== false};
  if (token) refresh().catch(error => message(error.message,true));
})();
