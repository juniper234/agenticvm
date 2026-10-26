(function(){
  'use strict';
  const canvas=document.getElementById('court'),ctx=canvas.getContext('2d');
  const status=document.getElementById('status'),play=document.getElementById('play');
  const options=globalThis.PongConfig||{},e=globalThis.PongEngine;
  const colors={blue:'#9dc7e4',mint:'#a8d5bd',amber:'#e5c08b'};
  let s=e.create({target:5,speed:({easy:220,normal:260,fast:310})[options.pace]||260}),last=0,pointer=null,keys=new Set();
  function reset(){s=e.create({target:5,speed:s.speed});pointer=null;last=0;canvas.focus();}
  function move(event){const r=canvas.getBoundingClientRect();pointer=(event.clientY-r.top)/r.height*canvas.height;}
  canvas.addEventListener('pointermove',move);canvas.addEventListener('pointerdown',event=>{move(event);canvas.setPointerCapture(event.pointerId);canvas.focus();if(s.phase==='ready')e.launch(s);});
  canvas.addEventListener('pointerleave',()=>pointer=null);
  document.addEventListener('keydown',event=>{
    if(['ArrowUp','ArrowDown',' ','w','s','W','S'].includes(event.key))event.preventDefault();
    keys.add(event.key.toLowerCase());if(!event.repeat&&event.code==='Space')e.toggle(s);if(!event.repeat&&event.key.toLowerCase()==='r')reset();
    if(['ArrowUp','ArrowDown','w','s','W','S'].includes(event.key))pointer=null;
  });
  document.addEventListener('keyup',event=>keys.delete(event.key.toLowerCase()));
  window.addEventListener('blur',()=>{keys.clear();pointer=null;if(s.phase==='playing')e.toggle(s);});
  play.onclick=()=>{if(s.phase==='finished')reset();e.toggle(s);canvas.focus();};
  document.getElementById('restart').onclick=reset;
  function draw(){
    ctx.fillStyle='#171b1e';ctx.fillRect(0,0,720,420);
    ctx.strokeStyle='#394147';ctx.setLineDash([6,10]);ctx.beginPath();ctx.moveTo(360,16);ctx.lineTo(360,404);ctx.stroke();ctx.setLineDash([]);
    ctx.fillStyle='#dce1e5';ctx.font='40px ui-monospace,monospace';ctx.textAlign='center';ctx.fillText(s.score[0],295,57);ctx.fillText(s.score[1],425,57);
    ctx.fillStyle=colors[options.palette]||colors.blue;ctx.fillRect(s.left.x,s.left.y,s.left.w,s.left.h);
    ctx.fillStyle='#e4e7e9';ctx.fillRect(s.right.x,s.right.y,s.right.w,s.right.h);ctx.beginPath();ctx.arc(s.ball.x,s.ball.y,s.ball.r,0,Math.PI*2);ctx.fill();
    if(s.phase!=='playing'){
      ctx.fillStyle='rgba(17,19,21,.8)';ctx.fillRect(180,148,360,130);
      ctx.fillStyle='#eee';ctx.font='24px system-ui,sans-serif';
      ctx.fillText(s.phase==='ready'?'Ready to play':s.phase==='paused'?'Paused':s.winner===0?'You win':'Computer wins',360,196);
      ctx.fillStyle='#aeb5ba';ctx.font='14px system-ui,sans-serif';ctx.fillText(s.phase==='finished'?'Press R or Restart for a new game':s.phase==='paused'?'Press Space to resume':'Press Start or tap the court',360,233);
    }
    const label=s.phase==='ready'?'First to 5':s.phase==='finished'?'Game over':s.phase==='paused'?'Paused':'First to 5';
    if(status.textContent!==label)status.textContent=label;
    play.textContent=s.phase==='ready'?'Start':s.phase==='playing'?'Pause':s.phase==='paused'?'Resume':'Play again';
  }
  function frame(now){const dt=last?Math.min((now-last)/1000,.025):0;last=now;e.step(s,dt,{axis:(keys.has('s')||keys.has('arrowdown')?1:0)-(keys.has('w')||keys.has('arrowup')?1:0),pointer});draw();requestAnimationFrame(frame);}
  // Read-only state snapshots support actual browser verification, not game control.
  globalThis.pongState=()=>JSON.parse(JSON.stringify(s));
  requestAnimationFrame(frame);
})();
