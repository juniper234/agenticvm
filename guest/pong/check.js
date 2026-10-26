import * as std from 'qjs:std';
std.loadScript('/workspace/pong/logic.js');
std.loadScript('/workspace/pong/engine.js');
const results=[];
function test(name,fn){try{fn();results.push({name,passed:true});}catch(e){results.push({name,passed:false,error:String(e)});}}
function eq(a,b){if(!Number.isFinite(a)||!Number.isFinite(b)||Math.abs(a-b)>1e-6)throw Error('expected '+b+', got '+a);}
const m=globalThis.PongMath,e=globalThis.PongEngine;
test('advance',()=>{eq(m.advance(10,5,2),20);eq(m.advance(10,-5,2),0);eq(m.advance(7,0,.5),7);eq(m.advance(0,1,.25),.25);});
test('bounce',()=>{eq(m.bounce(9),-9);eq(m.bounce(-7),7);eq(m.bounce(0),0);});
test('clamp',()=>{eq(m.clamp(-3,0,20),0);eq(m.clamp(25,0,20),20);eq(m.clamp(7,0,20),7);eq(m.clamp(-10,-5,5),-5);});
test('ready',()=>{const s=e.create();e.step(s,.02,{axis:1});eq(s.ticks,0);eq(s.score[0],0);});
test('start',()=>{const s=e.create();e.launch(s);if(s.phase!=='playing'||!s.ball.vx)throw Error('did not start');});
test('pause_resume',()=>{const s=e.create();e.launch(s);e.toggle(s);const x=s.ball.x;e.step(s,.02,{});eq(s.ball.x,x);e.toggle(s);if(s.phase!=='playing')throw Error('resume');});
test('keyboard_up',()=>{const s=e.create();e.launch(s);const y=s.left.y;e.step(s,.02,{axis:-1});if(s.left.y>=y)throw Error('up');});
test('keyboard_down',()=>{const s=e.create();e.launch(s);const y=s.left.y;e.step(s,.02,{axis:1});if(s.left.y<=y)throw Error('down');});
test('paddle_bounds',()=>{const s=e.create();e.launch(s);s.left.y=0;e.step(s,.02,{axis:-1});eq(s.left.y,0);s.left.y=342;e.step(s,.02,{axis:1});eq(s.left.y,342);});
test('pointer_bounds',()=>{const s=e.create();e.launch(s);e.step(s,.02,{pointer:-999});eq(s.left.y,0);e.step(s,.02,{pointer:9999});eq(s.left.y,342);});
test('top_wall',()=>{const s=e.create();e.launch(s);s.ball.y=7;s.ball.vy=-200;e.step(s,.02,{});if(s.ball.vy<=0||s.ball.y<7)throw Error('top bounce');});
test('bottom_wall',()=>{const s=e.create();e.launch(s);s.ball.y=413;s.ball.vy=200;e.step(s,.02,{});if(s.ball.vy>=0||s.ball.y>413)throw Error('bottom bounce');});
test('left_paddle_collision',()=>{const s=e.create();e.launch(s);s.ball={x:44,y:s.left.y+39,r:7,vx:-200,vy:0};e.step(s,.02,{});if(s.ball.vx<=0)throw Error('left collision');});
test('right_paddle_collision',()=>{const s=e.create();e.launch(s);s.ball={x:676,y:s.right.y+39,r:7,vx:200,vy:0};e.step(s,.02,{});if(s.ball.vx>=0)throw Error('right collision');});
test('score_left',()=>{const s=e.create();e.launch(s);s.ball.x=730;e.step(s,.02,{});eq(s.score[0],1);eq(s.ball.x,360);});
test('score_right',()=>{const s=e.create();e.launch(s);s.ball.x=-10;s.ball.vx=-260;e.step(s,.02,{});eq(s.score[1],1);});
test('first_to_five',()=>{const s=e.create();e.launch(s);s.score[0]=4;s.ball.x=730;e.step(s,.02,{});if(s.phase!=='finished'||s.winner!==0)throw Error('winner');});
test('restart_state',()=>{const s=e.create();eq(s.score[0],0);eq(s.score[1],0);if(s.phase!=='ready')throw Error('reset');});
test('long_rally_finite',()=>{const s=e.create({target:500});e.launch(s);for(let i=0;i<5000;i++){e.step(s,.016,{pointer:s.ball.y});if(!Number.isFinite(s.ball.x+s.ball.y+s.left.y+s.right.y))throw Error('nonfinite');if(s.left.y<0||s.left.y>342||s.right.y<0||s.right.y>342)throw Error('bounds');}});
test('player_can_win_through_controls',()=>{const s=e.create({speed:220,target:5});e.launch(s);for(let i=0;i<30000&&s.phase==='playing';i++)e.step(s,.016,{pointer:s.ball.y+32});if(s.phase!=='finished'||s.winner!==0||s.score[0]!==5)throw Error('player cannot win through legal paddle input');});
print(JSON.stringify({passed:results.every(r=>r.passed),checks:results.length,results}));
