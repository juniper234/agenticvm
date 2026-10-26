// Optional interoperability test using the SDK already pinned by the REA toolkit.
// Requires a running prototype session; changes only its temporary guest files.
import { Client } from '../tools/rea/node_modules/@modelcontextprotocol/client/dist/index.mjs';
import { StdioClientTransport } from '../tools/rea/node_modules/@modelcontextprotocol/client/dist/stdio.mjs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const workspace = path.resolve(root, process.argv[2] ?? 'runtime/prototype-smoke');
const env = Object.fromEntries(Object.entries(process.env).filter(([, value]) => value !== undefined));
env.PYTHONPATH = path.join(root, 'src');
const transport = new StdioClientTransport({
  command: process.env.AGENTICVM_PYTHON ?? 'python',
  args: ['-m', 'agenticvm.mcp', '--workspace', workspace], cwd: root, env, stderr: 'pipe',
});
const client = new Client({ name: 'agenticvm-live-check', version: '0.1.0' });
const passed = [];
const started = performance.now();
async function call(name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  assert.equal(result.isError, false, JSON.stringify(result));
  return JSON.parse(result.content.find(item => item.type === 'text').text);
}
try {
  await client.connect(transport);
  assert.equal(client.getServerVersion().name, 'agenticvm');
  const tools = await client.listTools();
  assert.equal(tools.tools.length, 18);
  passed.push('official SDK handshake and eighteen tool schemas');
  const status = await call('vm_status');
  assert.equal(status.result.guest_ready, true);
  assert.equal(status.result.guest.uid, 1000);
  passed.push('MCP reaches the live unprivileged Linux guest');
  const execution = await call('vm_exec', { argv: ['/bin/printf', '%s', 'mcp-live-ok'] });
  assert.equal(execution.result.stdout, 'mcp-live-ok');
  assert.equal(execution.result.exit_code, 0);
  passed.push('command execution and captured result');
  const text = 'Written through MCP\nUnicode: 🚀\n';
  await call('vm_write_file', { path: 'mcp-live.txt', text });
  const file = await call('vm_read_file', { path: 'mcp-live.txt' });
  assert.equal(file.text, text);
  assert.equal(Buffer.from(file.data_b64, 'base64').toString('utf8'), text);
  passed.push('UTF-8 file write and read through MCP');
  const job = await call('vm_exec', { argv: ['/bin/sleep', '20'], background: true });
  await call('vm_cancel', { job_id: job.result.job_id });
  let snapshot;
  for (let i = 0; i < 20; i++) {
    snapshot = await call('vm_poll', { job_id: job.result.job_id, wait_ms: 100 });
    if (snapshot.result.state === 'exited') break;
  }
  assert.equal(snapshot.result.cancelled, true);
  assert.equal(snapshot.result.state, 'exited');
  await call('vm_forget', { job_id: job.result.job_id });
  passed.push('background cancellation, polling and result release');
  if (status.result.profile === 'desktop') {
    const desktop = await call('vm_desktop_ready');
    assert.equal(desktop.result.ready, true);
    passed.push('MCP observes the live browser desktop');
    const screen = await client.callTool({ name: 'vm_screenshot', arguments: {} });
    assert.equal(screen.isError, false);
    const bitmap = screen.content.find(item => item.type === 'image');
    assert.equal(bitmap.mimeType, 'image/png');
    const png = Buffer.from(bitmap.data, 'base64');
    assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
    await writeFile(path.join(workspace, 'mcp-desktop.png'), png);
    passed.push('MCP returns the actual desktop as image content');
    await call('vm_open_url', { url: 'http://127.0.0.1:8080/' });
    let title;
    for (let i = 0; i < 20; i++) {
      title = await call('vm_exec', { argv: ['/usr/bin/xdotool', 'getactivewindow', 'getwindowname'] });
      if (title.result.stdout.includes('AgenticVM Desktop Ready')) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(title.result.stdout.includes('AgenticVM Desktop Ready'), title.result.stdout);
    passed.push('MCP navigates the real guest browser through desktop input');
    const message = 'MCP controls Linux: café λ';
    await call('vm_click', { x: 400, y: 266 });
    await call('vm_type', { text: message });
    await call('vm_click', { x: 60, y: 316 });
    for (let i = 0; i < 30; i++) {
      title = await call('vm_exec', { argv: ['/usr/bin/xdotool', 'getactivewindow', 'getwindowname'] });
      if (title.result.stdout.includes('Passed: ' + message)) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(title.result.stdout.includes('Passed: ' + message), title.result.stdout);
    passed.push('MCP mouse and literal Unicode input submit the real guest form');
    await call('vm_key', { keys: 'ctrl+l' });
    await call('vm_type', { text: 'http://127.0.0.1:8080/' });
    await call('vm_key', { keys: 'enter' });
    for (let i = 0; i < 30; i++) {
      title = await call('vm_exec', { argv: ['/usr/bin/xdotool', 'getactivewindow', 'getwindowname'] });
      if (title.result.stdout.includes('AgenticVM Desktop Ready')) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(title.result.stdout.includes('AgenticVM Desktop Ready'), title.result.stdout);
    passed.push('MCP key chords and literal URL input navigate the actual browser');
  }
  await call('vm_exec', { argv: ['/bin/rm', '-f', '/workspace/mcp-live.txt'] });
  const report = { sdk: '@modelcontextprotocol/client@2.3.1', passed, count: passed.length,
    elapsed_seconds: (performance.now() - started) / 1000, real_linux_guest: true };
  await mkdir(workspace, { recursive: true });
  await writeFile(path.join(workspace, 'mcp-live-report.json'), JSON.stringify(report, null, 2) + '\n');
  process.stdout.write(JSON.stringify(report) + '\n');
} finally {
  await client.close();
}
