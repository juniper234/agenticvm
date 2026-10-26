import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {createRequire} from 'node:module';
const require = createRequire(new URL('../integrations/dsh-remote-control/package.json', import.meta.url));
const {JSDOM} = require('jsdom');
const web = new URL('../src/agenticvm/web/',import.meta.url);
const dom = new JSDOM(fs.readFileSync(new URL('index.html',web),'utf8'),{url:'http://127.0.0.1/#token=fixture',runScripts:'outside-only',pretendToBeVisual:true});
const window = dom.window;
window.scrollTo=()=>{};window.setInterval=()=>0;
const $=id=>window.document.getElementById(id);
let snapshot={schema:1,revision:0,machines:{},oses:{},incoming:['test.iso'],incoming_folder:'C:/Beta/media/incoming',
  available:{desktop:true,android:true,windows:false},limits:{cpus_max:8},bridge:{launcher:'C:/Beta/agenticvm-desktop-mcp.cmd'}};
const values={memory:2048,cpus:2,width:1280,height:720,network:false,persistent:true};
const posts=[];
window.fetch=async (path,options={})=>{
  const body=options.body ? JSON.parse(options.body) : null;
  let result={status:'stopped',registered:false,profile:'desktop',settings:{memory:768,cpus:1,width:1024,height:768,network:true,persistent:true}};
  if(path==='/api/config') {
    if(body){
      posts.push(body);
      assert.equal(body.revision,snapshot.revision,'UI sends exact observed revision');
      if(body.operation==='save') snapshot={...snapshot,revision:snapshot.revision+1,machines:{...snapshot.machines,[body.profile]:body.settings}};
      else { const id='012345abcdef';snapshot={...snapshot,revision:snapshot.revision+1,os_id:id,
        oses:{[id]:{name:body.name,format:'iso'}},machines:{...snapshot.machines,['custom:'+id]:{...values,disk_gib:32,firmware:'bios',boot:'media',disk_bus:'sata'}}}; }
    }
    result=structuredClone(snapshot);
  }
  return {ok:true,headers:{get:()=> 'application/json'},json:async()=>({ok:true,result})};
};
for(const file of ['app.js','settings.js','glass-ui.js']) vm.runInContext(fs.readFileSync(new URL(file,web),'utf8'),dom.getInternalVMContext());
const flush=async()=>{for(let i=0;i<12;i++)await new Promise(resolve=>setTimeout(resolve,0));};
await flush();
assert.equal($('media-folder').textContent,'C:/Beta/media/incoming');
assert.equal($('profile').querySelector('option[value="windows"]').disabled,true);
$('memory').value='2048';$('cpus').value='2';$('display-size').value='1280x720';$('network').checked=false;
$('save-settings').click();await flush();
assert.deepEqual(posts[0].settings,values);
assert.match($('save-state').textContent,/saved/);
$('memory').value='4096';$('reload-settings').click();await flush();
assert.equal($('memory').value,'2048');
$('os-name').value='<img src=x onerror=alert(1)>';assert.equal($('os-media').value,'test.iso');
$('add-os').click();await flush();
assert.equal($('profile').value,'custom:012345abcdef');
assert.equal($('work-title').textContent,'<img src=x onerror=alert(1)>');
assert.equal($('work-title').querySelector('img'),null,'OS label remains literal text');
assert.equal($('custom-settings').hidden,false);
assert.equal($('memory').value,'2048');
vm.runInContext("displayState({status:'running',registered:true,profile:'custom',screen_ready:true,guest_ready:false,os_id:'012345abcdef'})",dom.getInternalVMContext());
assert.equal($('save-settings').disabled,true);assert.equal($('add-os').disabled,true);
assert.equal($('run-command').disabled,true);assert.equal($('send-text').disabled,false);
const mcp=JSON.parse($('bridge-config').value);
assert.equal(mcp.mcpServers['agenticvm-desktop'].command,'C:/Beta/tools/python-runtime/3.13.16/python.exe');
window.close();
console.log('Beta settings DOM checks passed: save/reload, library selection, literal labels, running guards and bridge config.');
