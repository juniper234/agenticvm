import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../src/agenticvm/web/app.js', import.meta.url), 'utf8');

function frontend() {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      value: id === 'memory' ? '768' : '', checked: ['network', 'persistent'].includes(id),
      classList: {toggle() {}}, handlers: {},
      replaceChildren(...children) { this.children = children; this.value = children[0]?.value || ''; },
      addEventListener(name, handler) { this.handlers[name] = handler; },
    });
    return elements.get(id);
  }
  const context = vm.createContext({
    URLSearchParams, location: {hash: '', pathname: '/'}, history: {replaceState() {}},
    Option: class { constructor(text, value) { this.text = text; this.value = value; } },
    sessionStorage: {getItem() { return ''; }, setItem() {}},
    localStorage: {getItem() { return ''; }, setItem() {}},
    document: {getElementById: element, documentElement: {dataset: {}}, querySelectorAll() { return []; }, addEventListener() {}},
    clearTimeout() {}, setTimeout() {}, setInterval() {},
  });
  vm.runInContext(source, context);
  return {element, update(state) { context.state = state; vm.runInContext('displayState(state)', context); }};
}

{
  const ui = frontend();
  ui.update({status: 'stopped', settings: {memory: 1024, network: false, persistent: false}});
  assert.equal(ui.element('memory').value, '1024');
  assert.equal(ui.element('network').checked, false);
  assert.equal(ui.element('persistent').checked, false);
  ui.element('memory').value = '768';
  ui.element('memory').handlers.change();
  ui.element('network').checked = true;
  ui.element('network').handlers.change();
  ui.update({status: 'running', settings: {memory: 1024, network: false, persistent: false}});
  assert.equal(ui.element('memory').value, '768');
  assert.equal(ui.element('network').checked, true);
}
{
  const ui = frontend();
  // An edit while the first HTTP status request is pending wins for that
  // control; the remaining controls still receive their saved values.
  ui.element('memory').value = '768';
  ui.element('memory').handlers.change();
  ui.update({status: 'stopped', settings: {memory: 1024, network: false, persistent: false}});
  assert.equal(ui.element('memory').value, '768');
  assert.equal(ui.element('network').checked, false);
  assert.equal(ui.element('persistent').checked, false);
}
{
  const ui = frontend();
  ui.update({status: 'starting'});
  assert.equal(ui.element('memory').value, '768');
  assert.equal(ui.element('network').checked, true);
  assert.equal(ui.element('persistent').checked, true);
  ui.update({status: 'running', settings: {memory: 768, network: false, persistent: true}});
  assert.equal(ui.element('network').checked, false);
}
console.log('settings checks passed');
