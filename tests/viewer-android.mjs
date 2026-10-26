import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../src/agenticvm/web/app.js', import.meta.url), 'utf8');
function frontend() {
  const elements = new Map(), actions = [];
  const navigation = [{hidden: true}, {hidden: true}, {hidden: true}];
  const chords = [{hidden: false}, {hidden: false}];
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      value: id === 'memory' ? '768' : '', checked: ['network', 'persistent'].includes(id),
      hidden: false, naturalWidth: 720, naturalHeight: 1280, handlers: {},
      classList: {toggle() {}},
      addEventListener(name, handler) { this.handlers[name] = handler; },
      replaceChildren(...children) { this.children = children; this.value = children[0]?.value || ''; },
      getBoundingClientRect() { return {left: 0, top: 0, width: 720, height: 1280}; },
      focus() {}, setPointerCapture() {},
    });
    return elements.get(id);
  }
  const context = vm.createContext({
    URLSearchParams, Option: class { constructor(text, value) { this.text = text; this.value = value; } },
    location: {hash: '', pathname: '/'}, history: {replaceState() {}},
    sessionStorage: {getItem() { return ''; }, setItem() {}},
    document: {getElementById: element, documentElement: {dataset: {}}, addEventListener() {},
      querySelectorAll(selector) { return selector === '.android-only' ? navigation : selector.includes('data-key') ? chords : []; }},
    clearTimeout() {}, setTimeout() {}, setInterval() {}, actions,
  });
  vm.runInContext(source, context);
  vm.runInContext('action = (request) => { actions.push(request); return Promise.resolve({}); };', context);
  return {element, context, navigation, chords, actions,
    run(code) { return vm.runInContext(code, context); },
    state(value) { context.state = value; vm.runInContext('displayState(state)', context); }};
}

{
  const ui = frontend();
  ui.state({status: 'running', profile: 'android', guest_ready: true, settings: {memory: 3072, network: false, persistent: true}});
  assert.equal(ui.element('profile').value, 'android');
  assert.equal(ui.element('profile').disabled, true);
  assert.equal(ui.element('memory').value, '3072');
  assert.equal(ui.element('android-apk').hidden, false);
  assert.equal(ui.element('ram-label').textContent, '3072 MiB');
  assert.equal(ui.element('guest-label').textContent, 'Android 15');
  assert.equal(ui.element('screen-readout').textContent, 'Press Start to open Android.');
  assert.ok(ui.navigation.every(button => !button.hidden));
  assert.ok(ui.chords.every(button => button.hidden));
  const down = {clientX: 100, clientY: 1000, pointerId: 1, preventDefault() {}};
  ui.element('screen').onpointerdown(down);
  ui.element('screen').onpointerup({...down, clientY: 200});
  assert.deepEqual(JSON.parse(JSON.stringify(ui.actions[0])), {action: 'swipe', x1: 100, y1: 1000, x2: 100, y2: 200});
  ui.element('screen').onpointerdown({...down, clientY: 500});
  ui.element('screen').onpointerup({...down, clientY: 500});
  assert.equal(ui.actions[1].action, 'click');
  assert.equal(ui.actions[1].y, 500);
}

{
  const ui = frontend();
  ui.element('profile').value = 'android';
  ui.element('profile').handlers.change();
  ui.element('profile').onchange();
  ui.state({status: 'stopped', profile: 'desktop', settings: {memory: 768, network: true, persistent: false}});
  assert.equal(ui.element('profile').value, 'android');
  assert.equal(ui.element('memory').value, '2560', 'A late Linux status must not replace Android memory choices');
  assert.equal(ui.element('network').checked, false);
  assert.equal(ui.element('persistent').checked, true);
  assert.equal(ui.element('ram-label').textContent, '2560 MiB');
}
console.log('Android viewer selection and touch checks passed');

// Drive the real upload handler, including body/headers, refusal and recovery.
for (const [error, expected] of [
  [null, 'Android app installed.'],
  [{code: 'android_command_failed', message: 'java.lang.IllegalArgumentException: Failed to parse APK file: /private/upload.apk\n at stack.frame'}, 'Android could not read this APK. Choose a valid, complete APK file.'],
  [{code: 'android_command_failed', message: 'INSTALL_FAILED_NO_MATCHING_ABIS'}, 'This APK uses an unsupported processor. Choose an APK that supports Android x86-64.'],
  [{code: 'android_command_failed', message: 'INSTALL_FAILED_UPDATE_INCOMPATIBLE'}, 'An app with a different signing key is already installed. Choose an update signed by the same publisher.'],
  [{code: 'android_command_failed', message: 'INSTALL_FAILED_VERSION_DOWNGRADE'}, 'A newer version of this app is already installed. Choose the same or a newer version.'],
  [{code: 'android_command_failed', message: 'INSTALL_FAILED_INSUFFICIENT_STORAGE'}, 'Android has insufficient storage to install this app.'],
  [{code: 'android_command_failed', message: 'unknown native stack trace'}, 'Android could not install this APK. Check that it supports Android 15 and x86-64.'],
  [{code: 'unauthorized', message: 'Open the viewer using its launch link.'}, 'Open the viewer using its launch link.'],
]) {
  const ui = frontend(), file = {name: 'test app.apk', size: 1234}, calls = [];
  ui.element('apk-file').files = [file];
  ui.context.fetch = async (path, options) => { calls.push({path, options}); return {ok: !error, json: async () => error ? {ok: false, error} : {ok: true, result: {installed: true}}}; };
  ui.run('status = () => {}; frame = () => {};');
  await ui.element('apk-file').onchange();
  assert.equal(calls.length, 1, 'Never replay an APK body automatically');
  assert.equal(calls[0].path, '/api/apk');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.headers['Content-Type'], 'application/vnd.android.package-archive');
  assert.ok(Object.hasOwn(calls[0].options.headers, 'X-AgenticVM-Token'));
  assert.equal(calls[0].options.body, file);
  assert.equal(ui.element('message').textContent, expected);
  assert.equal(ui.element('apk-file').value, '', 'Same file can be selected again after success or failure');
  assert.equal(ui.run('busyCount'), 0);
}
for (const file of [{name: 'bundle.aab', size: 10}, {name: 'too-big.apk', size: 512 * 1024 * 1024 + 1}]) {
  const ui = frontend();
  ui.element('apk-file').files = [file];
  ui.context.fetch = async () => { throw new Error('Invalid selection must not upload'); };
  await ui.element('apk-file').onchange();
  assert.equal(ui.element('message').textContent, 'Choose an APK no larger than 512 MiB.');
  assert.equal(ui.element('apk-file').value, '');
}
console.log('Android APK upload success, readable refusals and retry recovery checks passed');
