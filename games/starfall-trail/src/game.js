(() => {
"use strict";

const canvas = document.getElementById("game");
const ctx = canvas.getContext("2d");
const statusEl = document.getElementById("status");
const netStatus = document.getElementById("net-status");
const W = canvas.width, H = canvas.height;
const GRAVITY = 1850, MOVE_SPEED = 285, JUMP_SPEED = 690;
const keys = new Set();
const touch = { left:false, right:false, jump:false, power:false };
let touchJumpQueued = false;
let gameOS = null, mp = null, mpRole = "local", savedRun = null, bestScore = 0;
const earned = new Set();
const sharedEarned = new Set();
let gameState = "title", lastTime = 0, cameraX = 0, elapsed = 0, score = 0;
let levelIndex = 0, lives = 4, totalCoins = 0, coinProgress = 0, levelCoins = 0;
let power = null, powerTimer = 0, shieldTimer = 0, doubleJump = false, doubleUsed = false;
let jumpWasDown = false, powerWasDown = false, checkpointX = 70, message = "", messageTimer = 0;
let boss = null, bossHits = 0, levelData = null, levelPlatforms = [], coins = [], powerups = [], enemies = [];
let remoteInput = {left:false,right:false,jump:false,power:false}, netSnapshotAt = 0, netInputAt = 0, netJumpQueued = false;
const player = {x:70,y:390,w:28,h:42,vx:0,vy:0,onGround:false,facing:1,invuln:0,spawnX:70};
const partner = {x:110,y:390,w:28,h:42,vx:0,vy:0,onGround:false,facing:1,invuln:0,spawnX:110,active:false};
const themes = [
  ["MOONLIT MEADOW","#182b57","#6b8bb0","#70c58b","#243f47"],
  ["MUSHROOM WOODS","#183e3a","#73b79a","#9acb73","#31584a"],
  ["SUNSET DUNES","#633d48","#e39b72","#d9bd69","#72523d"],
  ["FROST PEAKS","#24415c","#a9d5e8","#b6e3e9","#45657c"],
  ["EMBER CAVES","#351e3e","#b96e65","#e38b55","#513348"],
  ["SKY BRIDGES","#29436c","#8db9d8","#e4d18b","#3d5875"],
  ["CRYSTAL MINES","#252c59","#8e91ce","#79d8d0","#41446e"],
  ["TIDAL RUINS","#123b54","#5ea9b6","#7dcbb6","#28566a"],
  ["CLOUD KINGDOM","#52608b","#c0c8e8","#f0e5ad","#65749b"],
  ["SHADOW GARDEN","#202c39","#718d84","#91b78a","#354b4c"],
  ["GOLDEN CANYON","#60402f","#d59a58","#e5c36f","#765239"],
  ["CLOCKWORK CITY","#303b53","#9ca7b4","#c5b47c","#505c69"],
  ["BLOSSOM HILLS","#603d64","#d99ab8","#a9d98b","#785078"],
  ["STORM COAST","#1b344c","#7698ae","#8dc2b8","#38576a"],
  ["LAVA FIELDS","#4a2226","#d46e4f","#e7a35a","#6b3531"],
  ["STARLIGHT LAKE","#202d5d","#839fd1","#8bd8db","#354b75"],
  ["ANCIENT TEMPLE","#4b4536","#b9a77b","#a6bd83","#655b43"],
  ["WINDY CLIFFS","#294456","#8bb6c8","#b5d9a2","#45677a"],
  ["NEBULA GATE","#31264f","#9c79c5","#7bd8d1","#4d3c70"],
  ["THE LAST BEACON","#352b53","#d0a4a5","#ffdc83","#604b68"]
];
const bossNames = ["MOSSBACK THE MIGHTY","FROSTFANG","CINDER COLOSSUS","THE STAR WARDEN"];
const bossColors = ["#78a85d","#7cc7e8","#e4774f","#b18ce8"];
const bossLevelIndexes = new Set([4,9,14,19]);

function rand(seed) { let x=Math.sin(seed*127.1+311.7)*43758.5453; return x-Math.floor(x); }
function setStatus(t) { statusEl.textContent=t; }
function overlap(a,b) { return a.x < b.x+b.w && a.x+a.w > b.x && a.y < b.y+b.h && a.y+a.h > b.y; }
function say(t) { message=t; messageTimer=2.1; }

function buildLevel(index) {
  const seed=index+1, theme=themes[index], worldW=3000;
  const ps=[{x:0,y:470,w:520,h:100},{x:690,y:470,w:500,h:100},{x:1370,y:470,w:520,h:100},{x:2070,y:470,w:930,h:100}];
  const styles=[
    [[220,380,145],[440,315,135],[760,380,140],[1000,320,150],[1450,370,155],[1700,300,150],[2140,375,150],[2400,310,155],[2700,365,150]],
    [[180,350,180],[430,285,140],[740,355,170],[990,270,145],[1430,340,170],[1680,275,160],[2130,350,180],[2400,280,160],[2700,340,170]],
    [[250,390,120],[440,325,120],[800,390,130],[1030,300,130],[1450,385,130],[1670,300,130],[2150,385,130],[2390,310,130],[2700,380,130]],
    [[150,360,180],[400,300,180],[760,365,160],[1000,290,160],[1430,360,180],[1680,285,180],[2110,360,180],[2390,290,160],[2700,350,180]]
  ];
  const pattern=styles[index%4];
  pattern.forEach((v,i)=>{
    const jitter=Math.floor((rand(seed*19+i)-.5)*34);
    ps.push({x:v[0]+jitter,y:v[1]+jitter*.35,w:v[2]+Math.floor(rand(seed*31+i)*35),h:20});
  });
  // A unique floating stepping-stone arrangement per level.
  for(let i=0;i<5;i++){
    const x=560+i*420+Math.floor((rand(seed*43+i)-.5)*90);
    const y=250+Math.floor(rand(seed*53+i)*100);
    ps.push({x,y,w:80+Math.floor(rand(seed*61+i)*55),h:18});
  }
  const cs=[];
  for(let i=0;i<22;i++){
    const x=150+i*125+Math.floor((rand(seed*71+i)-.5)*34);
    const candidates=ps.filter(p=>x>=p.x+12&&x<=p.x+p.w-8);
    const p=candidates.length?candidates[i%candidates.length]:{x,y:420,w:90,h:20};
    cs.push({x,y:Math.max(190,p.y-35-(i%3)*10),r:10,got:false,phase:i*.5});
  }
  const es=[];
  for(let i=0;i<4;i++){
    const x=520+i*610+Math.floor(rand(seed*83+i)*100);
    es.push({x,y:0,min:x-70,max:x+110,v:(i%2? -1:1)*(54+index*1.7),w:32,h:28,alive:true});
  }
  return {worldW,theme,platforms:ps,coins:cs,enemies:es,goal:{x:2860,y:370,w:34,h:100}};
}
function resetLevel(keepPlayer=true) {
  levelData=buildLevel(levelIndex);
  levelPlatforms=levelData.platforms;
  coins=levelData.coins;
  enemies=levelData.enemies;
  powerups=[];
  boss=null; bossHits=0;
  if (bossLevelIndexes.has(levelIndex)) {
    const bossNo=[4,9,14,19].indexOf(levelIndex);
    boss={x:2470,y:390,w:100,h:80,v:95+bossNo*12,health:3,maxHealth:3,name:bossNames[bossNo],color:bossColors[bossNo],attack:0};
    say(`MINI-BOSS: ${boss.name}`);
  }
  player.x=checkpointX=70; player.y=390; player.vx=0; player.vy=0; player.invuln=1;
  player.onGround=false; player.spawnX=70;
  partner.x=110; partner.y=390; partner.vx=partner.vy=0;
  cameraX=0; elapsed=0; levelCoins=0;
}
function resetRun() {
  levelIndex=0; lives=4; totalCoins=0; coinProgress=0; score=0;
  earned.clear(); sharedEarned.clear();
  power=null; powerTimer=0; shieldTimer=0; doubleJump=false; doubleUsed=false;
  checkpointX=70; resetLevel(); gameState="playing"; setStatus("LEVEL 1 / 20");
}
function continueRun() {
  if (!savedRun || mpRole !== "local") return;
  const run=savedRun;
  levelIndex=run.level-1; lives=run.lives; totalCoins=run.totalCoins;
  coinProgress=run.coinProgress; score=run.score;
  power=null; powerTimer=0; shieldTimer=0; doubleJump=false; doubleUsed=false;
  resetLevel(); gameState="playing"; setStatus(`LEVEL ${levelIndex+1} / 20`);
}
function loseLife(who=player) {
  if (shieldTimer>0) return;
  lives--;
  if (lives<=0) { gameState="lost"; say("OUT OF LIVES"); saveProgress(); return; }
  who.x=checkpointX; who.y=300; who.vx=0; who.vy=0; who.invuln=1.8;
  say(`LIFE LOST · ${lives} LEFT`);
}
function saveProgress() {
  if(!gameOS) return;
  bestScore=Math.max(bestScore,score);
  savedRun=gameState==="playing"||gameState==="paused" ? {level:levelIndex+1,lives,totalCoins,coinProgress,score} : null;
  document.getElementById("continue-button").disabled=!savedRun||mpRole!=="local";
  gameOS.save.set({bestScore,run:savedRun}).catch(e=>{netStatus.textContent="Could not save progress: "+e.message;});
}
function setAchievement(id) {
  if(mpRole==="host"&&partner.active)sharedEarned.add(id);
  if(earned.has(id)) return;
  earned.add(id);
  if(gameOS) gameOS.achievements.unlock(id).catch(e=>{earned.delete(id);netStatus.textContent="Achievement sync failed: "+e.message;});
}
function collectCoin(c) {
  c.got=true; totalCoins++; levelCoins++; score+=100; coinProgress++;
  if (coinProgress>=10) { coinProgress-=10; lives++; score+=250; say("10 COINS! EXTRA LIFE +1"); }
  setAchievement("first-coin");
  if(totalCoins>=100)setAchievement("coin-hoarder");
}
function spawnPowerup() {
  const choices=["shield","double","speed","life"];
  const type=choices[Math.floor(Math.random()*choices.length)];
  const p=levelPlatforms[Math.floor(Math.random()*levelPlatforms.length)];
  powerups.push({x:p.x+p.w/2-12,y:p.y-30,w:24,h:24,type,phase:Math.random()*6});
}
function collectPowerup(p) {
  if(p.type==="shield"){shieldTimer=9;say("STAR SHIELD · 9 SECONDS");}
  if(p.type==="double"){doubleJump=true;doubleUsed=false;say("MOON BOOTS · DOUBLE JUMP");}
  if(p.type==="speed"){power="speed";powerTimer=8;say("WIND DASH · 8 SECONDS");}
  if(p.type==="life"){lives++;say("HEART PICKUP · +1 LIFE");}
  score+=150;
}
function jump(who) {
  if(who.onGround){who.vy=-JUMP_SPEED;who.onGround=false;if(who===player)doubleUsed=false;}
  else if(who===player&&doubleJump&&!doubleUsed){who.vy=-JUMP_SPEED*.86;doubleUsed=true;}
}
function collidePlatforms(who,oldY) {
  who.onGround=false;
  for(const p of levelPlatforms){
    if(who.x+who.w<=p.x||who.x>=p.x+p.w)continue;
    if(who.vy>=0&&oldY+who.h<=p.y+8&&who.y+who.h>=p.y){who.y=p.y-who.h;who.vy=0;who.onGround=true;}
    else if(who.vy<0&&oldY>=p.y+p.h-4&&who.y<=p.y+p.h){who.y=p.y+p.h;who.vy=0;}
  }
}
function readInput() {
  let left=keys.has("ArrowLeft")||keys.has("KeyA")||touch.left;
  let right=keys.has("ArrowRight")||keys.has("KeyD")||touch.right;
  let jumpDown=keys.has("Space")||keys.has("KeyZ")||keys.has("ArrowUp")||keys.has("KeyW")||touch.jump||touchJumpQueued;
  touchJumpQueued=false;
  let powerDown=keys.has("KeyX")||touch.power;
  let connected=false;
  try {
    const pads=Array.from(navigator.getGamepads?.()||[]).filter(Boolean).sort((a,b)=>a.index-b.index);
    const pad=pads[0];
    if(pad){
      connected=true;const a=pad.axes||[],b=pad.buttons||[];
      left ||= !!b[14]?.pressed||(a[0]??0)<-.35;
      right ||= !!b[15]?.pressed||(a[0]??0)>.35;
      jumpDown ||= !!(b[0]?.pressed||b[1]?.pressed||b[12]?.pressed);
      powerDown ||= !!b[2]?.pressed;
    }
  } catch(_){}
  return {left,right,jump:jumpDown,power:powerDown,connected};
}
function updatePlayer(who,input,dt,isRemote=false) {
  const dir=(input.right?1:0)-(input.left?1:0);
  who.vx=dir*MOVE_SPEED*(power==="speed"&&!isRemote?1.35:1);
  if(dir)who.facing=dir;
  if(input.jump&&!who._jumpWas)jump(who);
  who._jumpWas=input.jump;
  const oldY=who.y;who.x=Math.max(0,Math.min(levelData.worldW-who.w,who.x+who.vx*dt));
  who.vy=Math.min(1000,who.vy+GRAVITY*dt);who.y+=who.vy*dt;
  collidePlatforms(who,oldY);
  if(who.y>H+90)loseLife(who);
  if(who.invuln>0)who.invuln-=dt;
}
function updateBoss(dt) {
  if(!boss)return;
  boss.x+=boss.v*dt;
  if(boss.x<2250||boss.x>2750)boss.v*=-1;
  boss.attack+=dt;
  for(const who of partner.active?[player,partner]:[player]){
    if(!boss||!overlap(who,boss))continue;
    if(who.vy>100&&who.y+who.h-boss.y<28){
      boss.health--;who.vy=-480;score+=300;say(`BOSS HIT · ${boss.health} LEFT`);
      if(boss.health<=0){score+=1500;boss=null;setAchievement("boss-breaker");say("MINI-BOSS DEFEATED!");}
    } else if(who.invuln<=0&&shieldTimer<=0){loseLife(who);}
  }
}
function nextLevel() {
  if(levelIndex>=19){gameState="won";score+=lives*500+totalCoins*10;setAchievement("trail-master");saveProgress();return;}
  levelIndex++;checkpointX=70;resetLevel();setStatus(`LEVEL ${levelIndex+1} / 20`);saveProgress();
}
function update(dt) {
  const input=readInput();
  const now=performance.now();
  if(mpRole==="client"){
    netJumpQueued ||= input.jump;
    if(now-netInputAt>=80){
      netInputAt=now;
      sendNet({t:"input",left:input.left,right:input.right,jump:netJumpQueued,power:input.power});
      netJumpQueued=false;
    }
    if(levelData) cameraX=Math.max(0,Math.min(levelData.worldW-W,partner.x-W*.38));
    return;
  }
  if(mpRole==="host"&&partner.active&&now-netSnapshotAt>=100){
    netSnapshotAt=now;
    sendNet({t:"state",p:player,q:partner,level:levelIndex,lives,score,totalCoins,coinProgress,
      state:gameState,coins:coins.map(c=>c.got),enemies,powerups,boss,earned:[...sharedEarned]});
  }
  if(gameState==="paused"){if(input.jump&&!jumpWasDown)resumeGame();jumpWasDown=input.jump;return;}
  if(gameState!=="playing"){
    if(input.jump&&!jumpWasDown&&(gameState==="title"||gameState==="lost"||gameState==="won"))resetRun();
    jumpWasDown=input.jump;return;
  }
  if(input.connected)setStatus(`LEVEL ${levelIndex+1}/20 · CONTROLLER`);
  else setStatus(`LEVEL ${levelIndex+1}/20`);
  elapsed+=dt;if(messageTimer>0)messageTimer-=dt;
  if(shieldTimer>0)shieldTimer-=dt;
  if(powerTimer>0){powerTimer-=dt;if(powerTimer<=0)power=null;}
  updatePlayer(player,input,dt);
  if(gameState!=="playing")return;
  if(partner.active&&mpRole==="host")updatePlayer(partner,remoteInput,dt,true);
  if(gameState!=="playing")return;
  if(input.power&&!powerWasDown&&power==="burst"){enemies.forEach(e=>e.alive=false);power=null;say("STAR BURST!");}
  powerWasDown=input.power;jumpWasDown=input.jump;
  const players=partner.active?[player,partner]:[player];
  for(const c of coins)if(!c.got&&players.some(who=>overlap(who,{x:c.x-9,y:c.y-9,w:18,h:18})))collectCoin(c);
  for(const p of powerups)if(!p.got&&players.some(who=>overlap(who,p))){p.got=true;collectPowerup(p);}
  powerups=powerups.filter(p=>!p.got);
  if(Math.random()<dt*.055&&powerups.filter(p=>!p.got).length<2)spawnPowerup();
  for(const e of enemies){
    if(!e.alive)continue;e.x+=e.v*dt;if(e.x<e.min||e.x+e.w>e.max)e.v*=-1;e.y=470-e.h;
    for(const who of players)if(e.alive&&overlap(who,e)){
      if(who.vy>90&&who.y+who.h-e.y<18){e.alive=false;who.vy=-390;score+=200;}
      else if(who.invuln<=0&&shieldTimer<=0)loseLife(who);
    }
    if(gameState!=="playing")return;
  }
  updateBoss(dt);
  if(gameState!=="playing")return;
  const lead=Math.max(...players.map(who=>who.x));
  if(lead>checkpointX+750){checkpointX=Math.floor(lead/750)*750;say("CHECKPOINT REACHED");}
  if(players.some(who=>who.x+who.w>levelData.goal.x)&&(!boss)){nextLevel();}
  cameraX=Math.max(0,Math.min(levelData.worldW-W,player.x-W*.38));
}
function pauseGame(){if(mpRole!=="client"&&gameState==="playing"){gameState="paused";setStatus("PAUSED");saveProgress();}}
function resumeGame(){if(mpRole!=="client"&&gameState==="paused"){gameState="playing";setStatus(`LEVEL ${levelIndex+1}/20`);}}
async function quitGame(){
  if(gameState==="playing"||gameState==="paused")saveProgress();
  if(mpRole!=="local"&&!await leaveMultiplayer())return;
  gameState="title";resetLevel();setStatus("BACK AT TITLE");
}
function sendNet(data){
  if(mp) mp.send(data).catch(e=>{netStatus.textContent="Network send failed: "+e.message;});
}
function handleNetMessage(event){
  const msg=event && event.data;
  if(!msg||typeof msg!=="object")return;
  if(msg.t==="input"&&mpRole==="host"){remoteInput={left:!!msg.left,right:!!msg.right,jump:!!msg.jump,power:!!msg.power};}
  if(msg.t==="state"&&mpRole==="client"){
    if(!Number.isInteger(msg.level)||msg.level<0||msg.level>=themes.length||
       !msg.p||!msg.q||!Array.isArray(msg.coins)||!Array.isArray(msg.enemies)||!Array.isArray(msg.powerups)||
       !["title","playing","paused","won","lost"].includes(msg.state))return;
    const changedLevel=levelIndex!==msg.level, changedState=gameState!==msg.state;
    if(changedLevel){levelIndex=msg.level;levelData=buildLevel(levelIndex);levelPlatforms=levelData.platforms;coins=levelData.coins;}
    Object.assign(player,msg.p);Object.assign(partner,msg.q);
    lives=msg.lives;score=msg.score;totalCoins=msg.totalCoins;coinProgress=msg.coinProgress;gameState=msg.state;
    coins.forEach((c,i)=>{c.got=!!msg.coins[i];});
    enemies=msg.enemies;powerups=msg.powerups;boss=msg.boss;
    if(Array.isArray(msg.earned))msg.earned.forEach(id=>setAchievement(id));
    if(changedLevel||changedState)saveProgress();
    setStatus(gameState==="playing"?`LEVEL ${levelIndex+1}/20 · CO-OP`:`CO-OP · ${gameState.toUpperCase()}`);
  }
}
function onPlayerJoined(event){
  if(mpRole!=="host")return;
  sharedEarned.clear();
  partner.active=true;
  partner.x=player.x;partner.y=player.y;partner.vx=partner.vy=0;partner.invuln=1;
  netStatus.textContent=event.username+" joined your co-op game.";
}
function onPlayerLeft(event){
  if(mpRole!=="host")return;
  partner.active=false;remoteInput={left:false,right:false,jump:false,power:false};
  netStatus.textContent=event.username+" left your co-op game.";
}
function onRoomEnded(event){
  if(gameState==="playing"||gameState==="paused")saveProgress();
  mpRole="local";partner.active=false;netJumpQueued=false;remoteInput={left:false,right:false,jump:false,power:false};
  gameState="title";resetLevel();
  document.getElementById("pause-button").disabled=false;
  document.getElementById("invite-button").disabled=true;
  document.getElementById("friend-select").disabled=true;
  document.getElementById("continue-button").disabled=!savedRun;
  netStatus.textContent="Co-op ended: "+(event.reason||"Disconnected.");
}
async function connectGameOS(){
  if(!window.GameOS||window.parent===window){setStatus("STANDALONE MODE");return;}
  try{
    const info=await window.GameOS.ready();
    gameOS=window.GameOS;mp=gameOS.multiplayer;
    gameOS.on("message",handleNetMessage).on("join",onPlayerJoined).on("leave",onPlayerLeft).on("ended",onRoomEnded);
    const saved=await gameOS.save.get();
    if(saved&&Number.isFinite(saved.bestScore))bestScore=saved.bestScore;
    const run=saved&&saved.run;
    if(run&&Number.isInteger(run.level)&&run.level>=1&&run.level<=20&&
       Number.isInteger(run.lives)&&run.lives>0&&Number.isFinite(run.totalCoins)&&
       Number.isFinite(run.coinProgress)&&Number.isFinite(run.score)){
      savedRun=run;document.getElementById("continue-button").disabled=false;
    }
    setStatus("GAMEOS CONNECTED");
    document.getElementById("host-button").disabled=false;
    document.getElementById("join-button").disabled=false;
    netStatus.textContent="Host a room or join a public co-op game.";
    if(info.launch&&info.launch.join&&info.launch.room)await joinRoom(info.launch.join,info.launch.room);
  }catch(e){setStatus("GAMEOS OFFLINE · LOCAL PLAY");netStatus.textContent="Game OS connection failed: "+e.message;}
}
async function hostCoop(){
  if(!mp){netStatus.textContent="Launch inside GameOS to host an online room.";return;}
  try{
    if(mpRole!=="local"&&!await leaveMultiplayer())return;
    await mp.host({maxPlayers:2,public:true,mode:"coop"});
    mpRole="host";partner.active=false;
    document.getElementById("continue-button").disabled=true;
    netStatus.textContent="Room hosted. Invite a friend or wait for a public player.";
    resetRun();
    try {
      const friends=await mp.players(), select=document.getElementById("friend-select");
      select.replaceChildren(...friends.map(name=>{const option=document.createElement("option");option.value=name;option.textContent=name;return option;}));
      select.disabled=!friends.length;document.getElementById("invite-button").disabled=!friends.length;
    }catch(e){netStatus.textContent="Room hosted, but friends could not be loaded: "+e.message;}
  }catch(e){netStatus.textContent="Could not host room: "+(e.message||e);}
}
async function joinRoom(host,roomId){
  if(mpRole!=="local"&&!await leaveMultiplayer())throw new Error("Could not leave the current room.");
  mpRole="client";
  try{
    await mp.join(host,roomId);
    document.getElementById("pause-button").disabled=true;
    document.getElementById("continue-button").disabled=true;
    netStatus.textContent=`Joined ${host}. Waiting for the host.`;
  }catch(e){mpRole="local";throw e;}
}
async function joinCoop(){
  if(!mp){netStatus.textContent="Launch inside GameOS to join an online room.";return;}
  try{
    const rooms=await mp.listPublic();
    if(!Array.isArray(rooms)||!rooms.length){netStatus.textContent="No public Starfall Trail rooms found. Ask a friend to invite you.";return;}
    const room=rooms[0];
    if(!room.roomId||!room.host)throw new Error("The room is missing its host or room ID.");
    await joinRoom(room.host,room.roomId);
  }catch(e){netStatus.textContent="Could not join room: "+(e.message||e);}
}
async function leaveMultiplayer(){
  try{await mp.leave();}catch(e){netStatus.textContent="Could not leave room: "+e.message;return false;}
  mpRole="local";partner.active=false;netJumpQueued=false;remoteInput={left:false,right:false,jump:false,power:false};
  document.getElementById("pause-button").disabled=false;
  document.getElementById("invite-button").disabled=true;
  document.getElementById("friend-select").disabled=true;
  document.getElementById("continue-button").disabled=!savedRun;
  netStatus.textContent="Left multiplayer room.";
  return true;
}
function drawBackground(){
  const t=levelData?.theme||themes[0],g=ctx.createLinearGradient(0,0,0,H);
  g.addColorStop(0,t[1]);g.addColorStop(1,t[2]);ctx.fillStyle=g;ctx.fillRect(0,0,W,H);
  for(let layer=0;layer<3;layer++){
    ctx.fillStyle=["#ffffff12","#07152c35","#07152c65"][layer];
    ctx.beginPath();ctx.moveTo(0,H);
    for(let x=-80;x<=W+100;x+=80){const wx=x+cameraX*(.1+layer*.1);ctx.lineTo(x,360+layer*43+Math.sin(wx*.006+layer)*25+Math.sin(wx*.013)*13);}
    ctx.lineTo(W,H);ctx.closePath();ctx.fill();
  }
  for(let i=0;i<60;i++){const x=((i*173-cameraX*.18)%(W+30)+W+30)%(W+30),y=28+(i*71)%230;ctx.fillStyle=i%4===0?"#ffe7a0":"#d8eaff";ctx.globalAlpha=.3+(i%5)*.1;ctx.fillRect(x,y,2,2);}
  ctx.globalAlpha=1;
}
function drawWorld(){
  ctx.save();ctx.translate(-cameraX,0);
  const ground=levelData.theme[4],top=levelData.theme[3];
  for(const p of levelPlatforms){ctx.fillStyle=ground;ctx.fillRect(p.x,p.y,p.w,p.h);ctx.fillStyle=top;ctx.fillRect(p.x,p.y,p.w,7);ctx.fillStyle="#ffffff18";for(let x=p.x+8;x<p.x+p.w-4;x+=29)ctx.fillRect(x,p.y+17,13,4);}
  for(const c of coins){if(c.got)continue;const bob=Math.sin(elapsed*4+c.phase)*4;ctx.fillStyle="#ffcf52";ctx.beginPath();ctx.ellipse(c.x,c.y+bob,8,11,0,0,Math.PI*2);ctx.fill();ctx.fillStyle="#fff1a5";ctx.fillRect(c.x-2,c.y-6+bob,3,7);}
  for(const p of powerups){if(p.got)continue;const bob=Math.sin(elapsed*4+p.phase)*4;ctx.fillStyle=p.type==="shield"?"#72d9ff":p.type==="double"?"#b6a2ff":p.type==="speed"?"#70e3d1":"#ff8d9b";ctx.fillRect(p.x,p.y+bob,p.w,p.h);ctx.fillStyle="#fff";ctx.font="bold 13px monospace";ctx.textAlign="center";ctx.fillText(p.type==="shield"?"S":p.type==="double"?"2":p.type==="speed"?"W":"+",p.x+12,p.y+17+bob);}
  for(const e of enemies){if(!e.alive)continue;ctx.fillStyle="#57365d";ctx.fillRect(e.x,e.y+5,e.w,e.h-5);ctx.fillStyle="#d08ab0";ctx.fillRect(e.x+4,e.y,e.w-8,12);ctx.fillStyle="#fff";ctx.fillRect(e.x+7,e.y+8,5,6);ctx.fillRect(e.x+21,e.y+8,5,6);}
  if(boss){ctx.fillStyle=boss.color;ctx.fillRect(boss.x,boss.y+14,boss.w,boss.h-14);ctx.fillStyle="#ffffff";ctx.fillRect(boss.x+18,boss.y+25,12,12);ctx.fillRect(boss.x+68,boss.y+25,12,12);ctx.fillStyle="#19213b";ctx.fillRect(boss.x+22,boss.y+29,5,6);ctx.fillRect(boss.x+72,boss.y+29,5,6);ctx.fillStyle="#ffcf69";ctx.fillRect(boss.x+28,boss.y+58,45,7);}
  const goal=levelData.goal;ctx.fillStyle="#d9e6ef";ctx.fillRect(goal.x+13,goal.y,7,100);ctx.fillStyle="#ffcf69";ctx.beginPath();ctx.moveTo(goal.x+20,goal.y+4);ctx.lineTo(goal.x+67,goal.y+20);ctx.lineTo(goal.x+20,goal.y+36);ctx.closePath();ctx.fill();
  drawHero(player,"#70e3d1");
  if(partner.active)drawHero(partner,"#ff9bce");
  ctx.restore();
}
function drawHero(p,accent){
  if(p.invuln<=0||Math.floor(elapsed*12)%2===0){ctx.fillStyle="#192b49";ctx.fillRect(p.x+4,p.y+4,20,38);ctx.fillStyle="#f3a65e";ctx.fillRect(p.x+5,p.y+3,19,17);ctx.fillStyle="#f7d7a2";ctx.fillRect(p.x+7,p.y+10,15,9);ctx.fillStyle="#315b9a";ctx.fillRect(p.x+2,p.y+19,24,16);ctx.fillStyle=accent;ctx.fillRect(p.x+3,p.y+21,22,6);ctx.fillStyle="#26324e";ctx.fillRect(p.x+3,p.y+35,9,7);ctx.fillRect(p.x+17,p.y+35,9,7);ctx.fillStyle="#fff";ctx.fillRect(p.x+(p.facing>0?17:7),p.y+11,3,4);}
  if(p===player&&shieldTimer>0){ctx.strokeStyle="#8de4ff";ctx.lineWidth=3;ctx.beginPath();ctx.arc(p.x+14,p.y+21,29,0,Math.PI*2);ctx.stroke();}
}
function overlay(title,sub,detail){
  ctx.fillStyle="#081329d9";ctx.fillRect(0,0,W,H);ctx.textAlign="center";
  ctx.fillStyle="#70e3d1";ctx.font="bold 18px monospace";ctx.fillText("✦ STARFALL TRAIL ✦",W/2,H/2-105);
  ctx.fillStyle="#fff";ctx.font="bold 40px monospace";ctx.fillText(title,W/2,H/2-45);
  ctx.fillStyle="#d3e3ff";ctx.font="17px monospace";ctx.fillText(sub,W/2,H/2+1);
  ctx.fillStyle="#ffd77b";ctx.font="bold 15px monospace";ctx.fillText(detail,W/2,H/2+55);
  ctx.fillStyle="#9eb3d5";ctx.font="12px monospace";ctx.fillText("ARROWS / A-D MOVE · SPACE / Z JUMP · X POWER",W/2,H/2+103);
  ctx.fillText("CONTROLLER: D-PAD / STICK + A · TOUCH BUTTONS ON MOBILE",W/2,H/2+127);
}
function render(){
  ctx.clearRect(0,0,W,H);drawBackground();drawWorld();
  ctx.textAlign="left";ctx.font="bold 16px monospace";ctx.fillStyle="#fff";
  ctx.fillText(`LEVEL ${levelIndex+1}/20 · ${levelData.theme[0]}`,22,29);
  ctx.fillStyle="#ffcf52";ctx.fillText(`COINS ${coinProgress}/10  TOTAL ${totalCoins}`,22,54);
  ctx.fillStyle="#ff9b9b";ctx.fillText(`LIVES ${lives}`,22,79);
  ctx.fillStyle="#d9e7ff";ctx.textAlign="right";ctx.fillText(`SCORE ${score}`,W-22,29);
  if(boss){ctx.textAlign="center";ctx.fillStyle="#fff";ctx.fillText(`${boss.name} · ${boss.health}/${boss.maxHealth}`,W/2,30);ctx.fillStyle="#412d49";ctx.fillRect(W/2-100,40,200,9);ctx.fillStyle=boss.color;ctx.fillRect(W/2-100,40,200*(boss.health/boss.maxHealth),9);}
  if(messageTimer>0){ctx.textAlign="center";ctx.font="bold 16px monospace";ctx.fillStyle="#fff0a5";ctx.fillText(message,W/2,105);}
  if(gameState==="title")overlay("STARFALL TRAIL","20 levels · 4 mini-bosses · stackable lives","PRESS ENTER / A TO START");
  if(gameState==="paused")overlay("PAUSED","Your adventure is on hold.","PRESS ESC / A TO RESUME");
  if(gameState==="lost")overlay("GAME OVER","You ran out of lives.","PRESS ENTER / A TO TRY AGAIN");
  if(gameState==="won")overlay("TRAIL COMPLETE!","You cleared all 20 levels and four mini-bosses.","PRESS ENTER / A TO PLAY AGAIN");
}
function loop(now){const dt=Math.min(.033,(now-lastTime)/1000||0);lastTime=now;update(dt);render();requestAnimationFrame(loop);}
window.addEventListener("gamepadconnected",e=>setStatus("CONTROLLER CONNECTED"));
window.addEventListener("gamepaddisconnected",()=>setStatus("KEYBOARD / CONTROLLER READY"));
window.addEventListener("keydown",e=>{
  if(["ArrowLeft","ArrowRight","ArrowUp","Space"].includes(e.code))e.preventDefault();
  keys.add(e.code);
  if(e.code==="Escape"||e.code==="KeyP"){if(gameState==="playing")pauseGame();else if(gameState==="paused")resumeGame();}
  if(e.code==="Enter"&&mpRole!=="client"&&gameState!=="playing"&&gameState!=="paused")resetRun();
});
window.addEventListener("keyup",e=>keys.delete(e.code));
window.addEventListener("blur",()=>{keys.clear();touchJumpQueued=false;Object.keys(touch).forEach(k=>touch[k]=false);});
document.querySelectorAll("[data-control]").forEach(b=>{
  const k=b.dataset.control;
  const down=e=>{e.preventDefault();touch[k]=true;if(k==="jump")touchJumpQueued=true;try{b.setPointerCapture(e.pointerId);}catch(_){}};
  const up=e=>{e.preventDefault();touch[k]=false;};
  b.addEventListener("pointerdown",down);b.addEventListener("pointerup",up);b.addEventListener("pointercancel",up);b.addEventListener("lostpointercapture",up);
});
document.getElementById("pause-button").addEventListener("click",()=>gameState==="paused"?resumeGame():pauseGame());
document.getElementById("continue-button").addEventListener("click",continueRun);
document.getElementById("quit-button").addEventListener("click",quitGame);
document.getElementById("host-button").addEventListener("click",hostCoop);
document.getElementById("join-button").addEventListener("click",joinCoop);
document.getElementById("invite-button").addEventListener("click",async()=>{
  try{const friend=document.getElementById("friend-select").value;await mp.invite(friend);netStatus.textContent="Invite sent to "+friend+".";}
  catch(e){netStatus.textContent="Could not invite friend: "+e.message;}
});
const fullscreenButton=document.getElementById("fullscreen-button");
const cabinet=document.querySelector(".cabinet");
fullscreenButton.hidden=!document.fullscreenEnabled;
fullscreenButton.addEventListener("click",async()=>{
  try {
    if(document.fullscreenElement) await document.exitFullscreen();
    else await cabinet.requestFullscreen();
  } catch(e) { setStatus("FULLSCREEN UNAVAILABLE: "+e.message); }
});
document.addEventListener("fullscreenchange",()=>{
  const active=document.fullscreenElement===cabinet;
  fullscreenButton.textContent=active?"EXIT FULLSCREEN":"FULLSCREEN";
  fullscreenButton.setAttribute("aria-pressed",String(active));
});
connectGameOS();resetLevel();requestAnimationFrame(loop);
})();