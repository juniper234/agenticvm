import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../src/agenticvm/web/app.js', import.meta.url), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
const okJson = () => ({
  ok: true,
  headers: {get: () => 'application/json'},
  json: async () => ({ok: true, result: {}}),
});
const failedJson = (code, message) => ({
  ok: false,
  headers: {get: () => 'application/json'},
  json: async () => ({ok: false, error: {code, message}}),
});
const binary = (read = async () => 'download bytes') => ({
  ok: true, headers: {get: () => 'application/octet-stream'}, blob: read,
});

function frontend(fetch) {
  const elements = new Map(), timers = [], downloads = [], blobs = [];
  function element(id) {
    if (!elements.has(id)) {
      const classes = new Set();
      elements.set(id, {
        value: id === 'memory' ? '768' : '', checked: false, hidden: false,
        classList: {
          toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
          contains(name) { return classes.has(name); },
        },
        addEventListener() {},
      });
    }
    return elements.get(id);
  }
  const context = vm.createContext({
    URLSearchParams,
    URL: {createObjectURL(blob) { blobs.push(blob); return 'blob:verified'; }, revokeObjectURL() {}},
    location: {hash: '', pathname: '/'}, history: {replaceState() {}},
    sessionStorage: {getItem() { return ''; }, setItem() {}},
    document: {
      documentElement: {dataset: {view: 'display'}},
      getElementById: element, querySelectorAll() { return []; }, addEventListener() {},
      createElement(tag) {
        assert.equal(tag, 'a');
        return {click() { downloads.push({href: this.href, name: this.download}); }};
      },
    },
    fetch, clearTimeout() {}, setInterval() {},
    setTimeout(callback, milliseconds) { timers.push({callback, milliseconds}); },
  });
  vm.runInContext(source, context);
  element('file-path').value = '/workspace/proof.txt';
  return {
    element, downloads, blobs,
    run(code) { return vm.runInContext(code, context); },
    async tick(milliseconds) {
      const index = timers.findIndex(timer => timer.milliseconds === milliseconds);
      assert.notEqual(index, -1, 'Expected pending ' + milliseconds + ' ms timer');
      timers.splice(index, 1)[0].callback();
      await flush();
    },
    pending(milliseconds) { return timers.some(timer => timer.milliseconds === milliseconds); },
  };
}

{
  const calls = [];
  let finishBody;
  const body = new Promise(resolve => { finishBody = resolve; });
  const ui = frontend(async path => {
    calls.push(path);
    return path.startsWith('/api/download') ? binary(() => body) : okJson();
  });
  ui.run("message('Old error', true); framePending = true; statusPending = true");
  const download = ui.element('download').onclick();
  const action = ui.run("action({action: 'key', keys: 'enter'})");
  await flush();
  assert.equal(calls.length, 0, 'Download waits for the in-flight screenshot');
  assert.equal(ui.element('download').disabled, true);
  ui.run('framePending = false');
  await ui.tick(50);
  assert.equal(calls.length, 0, 'Download also waits for the pending status request');
  ui.run('statusPending = false');
  await ui.tick(50);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].startsWith('/api/download?'));
  assert.equal(ui.downloads.length, 0, 'No download is reported before its body arrives');
  assert.equal(ui.element('download').disabled, true);
  finishBody('verified file bytes');
  await Promise.all([download, action]);
  assert.deepEqual(calls, ['/api/download?path=%2Fworkspace%2Fproof.txt', '/api/action']);
  assert.equal(ui.downloads.length, 1);
  assert.equal(ui.downloads[0].name, 'proof.txt');
  assert.equal(ui.blobs[0], 'verified file bytes');
  assert.equal(ui.element('message').textContent, 'Download started.');
  assert.equal(ui.element('message').classList.contains('error'), false);
  assert.equal(ui.element('download').disabled, false);
}
{
  let calls = 0;
  const ui = frontend(async () => ++calls === 1
    ? failedJson('busy', 'A desktop action is still running.') : binary());
  const download = ui.element('download').onclick();
  await flush();
  assert.equal(calls, 1);
  assert.equal(ui.downloads.length, 0);
  await ui.tick(350);
  await download;
  assert.equal(calls, 2, 'Only the pre-dispatch busy response is retried');
  assert.equal(ui.downloads.length, 1);
  assert.equal(ui.element('message').textContent, 'Download started.');
}
{
  let calls = 0;
  const ui = frontend(async () => {
    calls++;
    return failedJson('file_not_found', 'File does not exist.');
  });
  await ui.element('download').onclick();
  assert.equal(calls, 1);
  assert.equal(ui.pending(350), false);
  assert.equal(ui.downloads.length, 0);
  assert.equal(ui.element('message').textContent, 'File does not exist.');
  assert.equal(ui.element('message').classList.contains('error'), true);
}
{
  let calls = 0;
  const ui = frontend(async () => {
    calls++;
    return binary(async () => { throw new Error('File transfer interrupted.'); });
  });
  await ui.element('download').onclick();
  assert.equal(calls, 1, 'A body failure after successful dispatch is never retried');
  assert.equal(ui.downloads.length, 0);
  assert.equal(ui.element('message').textContent, 'File transfer interrupted.');
  assert.equal(ui.element('message').classList.contains('error'), true);
}
console.log('download queue checks passed');
