// ══════════════════════════════════════════════════════════════
// SNORT3 SOC — SECURITY OPERATIONS CENTER
// Professional SOC/SIEM Console with Advanced Analytics
// ══════════════════════════════════════════════════════════════

// ── XSS SANITIZATION ────────────────────────────────────────
function esc(s){if(!s)return'';const d=document.createElement('div');d.appendChild(document.createTextNode(String(s)));return d.innerHTML}
function safeIP(ip){return esc(String(ip||'?').replace(/[^0-9a-fA-F.:\/]/g,''))}
function safeMsg(m){return esc(String(m||'').substring(0,200))}
function safeSid(s){return esc(String(s||'?').replace(/[^0-9:]/g,''))}
function safePort(p){return esc(String(p||'?').replace(/[^0-9]/g,''))}
function safeProto(p){return esc(String(p||'?').replace(/[^A-Za-z0-9]/g,''))}

// ── CONSTANTS ──────────────────────────────────────────────
const CATS={
  recon:{label:"Scan/Recon",color:"#F59E0B",icon:"🔍",mitre:["T1046","T1018","T1110"]},
  web_attack:{label:"Web Attack",color:"#EF4444",icon:"🌐",mitre:["T1190","T1059","T1083"]},
  dos:{label:"DoS/DDoS",color:"#8B5CF6",icon:"⚡",mitre:["T1498","T1499"]},
  malware:{label:"Malware/C2",color:"#DC2626",icon:"🦠",mitre:["T1071","T1041","T1048"]},
};

const SEVS={
  low:{label:"Faible",color:"#10B981",range:"1-7"},
  medium:{label:"Moyen",color:"#F59E0B",range:"8-9"},
  high:{label:"Élevé",color:"#EF4444",range:"10-11"},
  critical:{label:"Critique",color:"#DC2626",range:"12+"}
};

const MITRE_NAMES={
  T1046:"Network Scan",T1018:"Remote Discovery",T1110:"Brute Force",
  T1190:"Exploit Public App",T1059:"Command Exec",T1083:"File Discovery",
  T1498:"Network DoS",T1499:"Endpoint DoS",T1071:"App Layer Proto",
  T1041:"Exfil Over C2",T1048:"Exfil Alt Proto",T1210:"Exploit Remote Svc",
  T1021:"Remote Services",T1090:"Proxy/TOR",T1568:"Dynamic Resolution"
};

const MITRE_TACTICS={
  "Reconnaissance":{color:"#10B981",techniques:["T1046","T1018"]},
  "Initial Access":{color:"#F59E0B",techniques:["T1190"]},
  "Execution":{color:"#EF4444",techniques:["T1059"]},
  "Credential Access":{color:"#DC2626",techniques:["T1110"]},
  "Lateral Movement":{color:"#8B5CF6",techniques:["T1210","T1021"]},
  "Command & Control":{color:"#06B6D4",techniques:["T1071","T1090"]},
  "Exfiltration":{color:"#F97316",techniques:["T1041","T1048"]},
  "Impact":{color:"#DC2626",techniques:["T1498","T1499"]},
  "Defense Evasion":{color:"#3B82F6",techniques:["T1568"]}
};

const SID_MITRE={
  9001001:"T1046",9001002:"T1046",9001003:"T1046",9001004:"T1046",9001005:"T1046",
  9001006:"T1046",9001007:"T1018",9001009:"T1046",9001010:"T1110",9002001:"T1083",
  9002002:"T1190",9002003:"T1190",9002004:"T1190",9002005:"T1059",9002006:"T1059",
  9002007:"T1190",9002008:"T1059",9002009:"T1083",9002010:"T1190",9002011:"T1190",
  9002012:"T1190",9002020:"T1498",9002021:"T1498",9002022:"T1498",9002025:"T1210",
  9002027:"T1021",9002028:"T1498",9003001:"T1071",9003002:"T1071",9003003:"T1059",
  9003004:"T1059",9003005:"T1071",9003006:"T1071",9003010:"T1048",9003011:"T1071",
  9003022:"T1041",9003030:"T1210",9003031:"T1110",9003032:"T1071",9003033:"T1059",
  9004001:"T1071",9004002:"T1071",9004003:"T1071",9004004:"T1071",9004005:"T1071",
  9004006:"T1568",9005001:"T1090",9005002:"T1090",9005003:"T1090",9005004:"T1090",
  9005005:"T1090",9005006:"T1090"
};

const PORT_SERVICES={
  22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",
  443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
  6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB"
};

const WIN_EVENTS={
  4624:{name:"Login Réussi",category:"Security",severity:"low",icon:"✅"},
  4625:{name:"Login Échoué",category:"Security",severity:"medium",icon:"❌"},
  4720:{name:"Utilisateur Créé",category:"Security",severity:"medium",icon:"👤"},
  4732:{name:"Admin Ajouté",category:"Security",severity:"high",icon:"⚠️"},
  4648:{name:"Login Explicite",category:"Security",severity:"low",icon:"🔑"},
  11:{name:"Erreur Kerberos",category:"System",severity:"medium",icon:"🔐"},
  7045:{name:"Service Installé",category:"System",severity:"high",icon:"⚙️"},
  1001:{name:"BSOD",category:"System",severity:"critical",icon:"💥"}
};

// ── GEO CACHE ────────────────────────────────────────────────
const geoCache={};

async function geoLookup(ip){
  if(geoCache[ip])return geoCache[ip];
  try{
    const r=await fetch(`https://ip-api.com/json/${ip}?fields=country,countryCode,lat,lon,org`);
    if(r.ok){const d=await r.json();if(d.lat){geoCache[ip]=d;return d;}}
  }catch(e){}
  return null;
}

// ── STATE ────────────────────────────────────────────────────
let S={
  alerts:[],winAlerts:[],filter:"all",search:"",sortDir:"desc",mitreFilter:null,
  connected:false,error:"",showConfig:false,tab:"snort",detailAlert:null,
  config:{url:"https://soc.your-domain.com/opensearch",username:"",password:""},
  refreshInterval:null,geoData:{},mapReady:false,lastUpdate:Date.now(),
  soundEnabled:false,lastAlertCount:0,loading:false
};

// ── HELPER FUNCTIONS ────────────────────────────────────────
function getCat(m){
  if(!m)return"other";
  if(m.startsWith("SCAN"))return"recon";
  if(m.startsWith("INTRUSION HTTP"))return"web_attack";
  if(m.startsWith("INTRUSION DOS"))return"dos";
  if(m.startsWith("MALWARE"))return"malware";
  return"other";
}

function getSev(l){
  if(l>=12)return"critical";
  if(l>=10)return"high";
  if(l>=8)return"medium";
  return"low";
}

function getMitre(sid){return SID_MITRE[parseInt(sid)]||null}

function formatTime(ts){
  try{return new Date(ts).toLocaleTimeString("fr-FR")}catch(e){return"--"}
}

function formatDate(ts){
  try{return new Date(ts).toLocaleDateString("fr-FR",{day:"2-digit",month:"short"})}catch(e){return"--"}
}

function timeSince(ts){
  try{
    const sec=Math.floor((Date.now()-new Date(ts).getTime())/1000);
    if(sec<60)return sec+"s";
    if(sec<3600)return Math.floor(sec/60)+"m";
    if(sec<86400)return Math.floor(sec/3600)+"h";
    return Math.floor(sec/86400)+"j";
  }catch(e){return"--"}
}

// ── API ──────────────────────────────────────────────────────
function authH(){return"Basic "+btoa(`${S.config.username}:${S.config.password}`)}

async function fetchAlerts(){
  if(!S.config.password)return;
  S.loading=true;
  render();
  try{
    // Snort alerts
    const r=await fetch(`${S.config.url}/wazuh-alerts-*/_search`,{
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":authH()},
      body:JSON.stringify({
        size:500,
        query:{bool:{must:[{match:{"rule.groups":"snort3"}}]}},
        sort:[{timestamp:{order:"desc"}}]
      })
    });
    if(!r.ok)throw new Error("HTTP "+r.status);
    const d=await r.json();
    if(d.hits?.hits?.length){
      const oldCount=S.alerts.length;
      S.alerts=d.hits.hits.map(h=>h._source);
      // Play sound if new critical alerts
      if(S.soundEnabled&&S.alerts.length>oldCount){
        const newCrit=S.alerts.slice(0,S.alerts.length-oldCount).filter(a=>getSev(a.rule?.level||0)==="critical");
        if(newCrit.length>0)playAlertSound();
      }
    }

    // Windows alerts
    const r2=await fetch(`${S.config.url}/wazuh-alerts-*/_search`,{
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":authH()},
      body:JSON.stringify({
        size:200,
        query:{bool:{must:[{match:{"agent.os.platform":"windows"}}]}},
        sort:[{timestamp:{order:"desc"}}]
      })
    });
    if(r2.ok){const d2=await r2.json();if(d2.hits?.hits?.length)S.winAlerts=d2.hits.hits.map(h=>h._source);}

    S.connected=true;S.error="";S.lastUpdate=Date.now();S.loading=false;
    // Geo lookup top IPs
    resolveGeo();
    render();
  }catch(e){S.error=e.message;S.connected=false;S.loading=false;render()}
}

async function resolveGeo(){
  const ips={};
  S.alerts.forEach(a=>{const ip=a.data?.src_addr;if(ip&&!S.geoData[ip])ips[ip]=1});
  const unique=Object.keys(ips).slice(0,15);
  for(const ip of unique){
    const g=await geoLookup(ip);
    if(g)S.geoData[ip]={lat:g.lat,lng:g.lon,country:g.country,code:g.countryCode,org:g.org};
    await new Promise(r=>setTimeout(r,250));
  }
  if(unique.length>0){S.mapReady=true;render();}
}

async function connect(){
  S.error="";
  await fetchAlerts();
  if(S.connected){
    if(S.refreshInterval)clearInterval(S.refreshInterval);
    S.refreshInterval=setInterval(fetchAlerts,15000);
  }
  S.showConfig=false;
  render();
}

function playAlertSound(){
  const audioCtx=new(window.AudioContext||window.webkitAudioContext)();
  const osc=audioCtx.createOscillator();
  const gain=audioCtx.createGain();
  osc.connect(gain);
  gain.connect(audioCtx.destination);
  osc.frequency.value=800;
  osc.type='sine';
  gain.gain.setValueAtTime(0.1,audioCtx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.01,audioCtx.currentTime+0.3);
  osc.start(audioCtx.currentTime);
  osc.stop(audioCtx.currentTime+0.3);
}

// ── STATS & ANALYTICS ────────────────────────────────────────
function stats(alerts){
  const cats={recon:0,web_attack:0,dos:0,malware:0};
  const sevs={low:0,medium:0,high:0,critical:0};
  const sources={};
  const mitreC={};
  const hourly={};
  const daily={};
  const ports={};
  const proto={TCP:0,UDP:0,ICMP:0};
  let crit=0;
  let totalTime=0;
  let validTimeCount=0;

  const now=Date.now();
  const last24h=now-86400000;
  const last50=alerts.slice(0,50);

  alerts.forEach(a=>{
    const cat=getCat(a.data?.msg);if(cats[cat]!==undefined)cats[cat]++;
    const sv=getSev(a.rule?.level||0);sevs[sv]++;if(sv==="critical"||sv==="high")crit++;
    const src=String(a.data?.src_addr||"?").replace(/[^0-9a-fA-F.:\/]/g,'');sources[src]=(sources[src]||0)+1;
    const m=getMitre(a.data?.sid);if(m)mitreC[m]=(mitreC[m]||0)+1;

    // Time stats
    try{
      const ts=new Date(a.timestamp).getTime();
      if(ts>last24h){
        totalTime+=now-ts;
        validTimeCount++;
      }
      const h=new Date(ts).getHours();hourly[h]=(hourly[h]||0)+1;
      const d=new Date(ts).toLocaleDateString("fr-FR");daily[d]=(daily[d]||0)+1;
    }catch(e){}

    // Port & protocol stats
    const port=a.data?.dst_port;if(port)ports[port]=(ports[port]||0)+1;
    const p=String(a.data?.proto||"").toUpperCase();if(proto[p]!==undefined)proto[p]++;
  });

  // MTTD (Mean Time To Detect) - avg time from alert to now for last 10
  const mttd=validTimeCount>0?(totalTime/validTimeCount/1000/60):0; // in minutes

  // Alert rate (alerts/minute) from last 50
  let alertRate=0;
  if(last50.length>=2){
    try{
      const firstTs=new Date(last50[0].timestamp).getTime();
      const lastTs=new Date(last50[last50.length-1].timestamp).getTime();
      const diffMin=(firstTs-lastTs)/1000/60;
      if(diffMin>0)alertRate=last50.length/diffMin;
    }catch(e){}
  }

  // Unique attackers last 24h
  const uniqueAttackers=new Set();
  alerts.forEach(a=>{
    try{
      if(new Date(a.timestamp).getTime()>last24h)uniqueAttackers.add(a.data?.src_addr);
    }catch(e){}
  });

  // Top port
  const topPort=Object.entries(ports).sort((a,b)=>b[1]-a[1])[0];

  // Get last 7 days for timeline
  const last7Days=[];
  for(let i=6;i>=0;i--){
    const d=new Date(now-i*86400000);
    const key=d.toLocaleDateString("fr-FR");
    last7Days.push({date:key,count:daily[key]||0,label:d.toLocaleDateString("fr-FR",{day:"2-digit",month:"short"})});
  }

  return{
    cats,sevs,crit,total:alerts.length,
    topSrc:Object.entries(sources).sort((a,b)=>b[1]-a[1]).slice(0,8),
    topMitre:Object.entries(mitreC).sort((a,b)=>b[1]-a[1]).slice(0,6),
    mitreC,hourly,daily,
    mttd:mttd.toFixed(1),
    alertRate:alertRate.toFixed(2),
    uniqueAttackers:uniqueAttackers.size,
    topPort:topPort?{port:topPort[0],count:topPort[1],service:PORT_SERVICES[topPort[0]]||"Unknown"}:null,
    proto,
    last7Days
  };
}

function filterA(){
  let f=S.alerts;
  if(S.filter!=="all")f=f.filter(a=>getCat(a.data?.msg)===S.filter);
  if(S.mitreFilter)f=f.filter(a=>getMitre(a.data?.sid)===S.mitreFilter);
  if(S.search){
    const s=S.search.toLowerCase();
    f=f.filter(a=>
      (a.data?.msg||"").toLowerCase().includes(s)||
      (a.data?.src_addr||"").includes(s)||
      (a.data?.dst_addr||"").includes(s)||
      (a.data?.sid||"").includes(s)||
      (getMitre(a.data?.sid)||"").toLowerCase().includes(s)
    );
  }
  return S.sortDir==="desc"?f:[...f].reverse();
}

// ── BLOCKED IPS (Active Response) ────────────────────────────
function getBlockedIPs(){
  const blocked=[];
  S.alerts.forEach(a=>{
    const desc=a.rule?.description||"";
    if(desc.includes("BLOCKED")||desc.includes("Active Response")){
      blocked.push({
        ip:a.data?.src_addr,
        timestamp:a.timestamp,
        reason:desc,
        sid:a.data?.sid,
        remaining:Math.max(0,300-(Date.now()-new Date(a.timestamp).getTime())/1000)
      });
    }
  });
  return blocked.filter(b=>b.remaining>0).slice(0,20);
}

// ── EXPORT FUNCTIONS ─────────────────────────────────────────
function exportCSV(){
  const filtered=filterA();
  let csv="Heure,Niveau,Message,SID,Source,Destination,Port,Proto,MITRE\n";
  filtered.forEach(a=>{
    const t=formatTime(a.timestamp);
    const level=a.rule?.level||"?";
    const msg=(a.data?.msg||"").replace(/,/g,";");
    const sid=a.data?.sid||"?";
    const src=a.data?.src_addr||"?";
    const dst=a.data?.dst_addr||"?";
    const port=a.data?.dst_port||"?";
    const proto=a.data?.proto||"?";
    const mitre=getMitre(a.data?.sid)||"";
    csv+=`${t},${level},"${msg}",${sid},${src},${dst},${port},${proto},${mitre}\n`;
  });
  downloadFile(csv,"snort3-alerts-"+Date.now()+".csv","text/csv");
}

function exportJSON(){
  const filtered=filterA();
  const json=JSON.stringify(filtered,null,2);
  downloadFile(json,"snort3-alerts-"+Date.now()+".json","application/json");
}

function downloadFile(content,filename,mimeType){
  const blob=new Blob([content],{type:mimeType});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=url;
  a.download=filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function generateReport(){
  const st=stats(S.alerts);
  const html=`<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport SOC - ${new Date().toLocaleDateString("fr-FR")}</title>
<style>
body{font-family:Arial,sans-serif;margin:40px;background:#fff;color:#000}
h1{color:#06B6D4;border-bottom:2px solid #06B6D4;padding-bottom:10px}
h2{color:#3B82F6;margin-top:30px}
.stat{display:inline-block;margin:10px 20px 10px 0;padding:10px 20px;background:#f0f9ff;border-left:4px solid #06B6D4}
.stat-label{font-size:12px;color:#64748B;text-transform:uppercase}
.stat-value{font-size:24px;font-weight:bold;color:#06B6D4}
table{width:100%;border-collapse:collapse;margin:20px 0}
th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#06B6D4;color:#fff}
.critical{color:#DC2626;font-weight:bold}
</style>
</head>
<body>
<h1>🛡️ Rapport SOC - Snort3 IDS</h1>
<p><strong>Date:</strong> ${new Date().toLocaleString("fr-FR")}</p>
<p><strong>Période:</strong> Dernières 24 heures</p>

<h2>Statistiques Générales</h2>
<div class="stat"><div class="stat-label">Total Alertes</div><div class="stat-value">${st.total}</div></div>
<div class="stat"><div class="stat-label">Critique/Élevé</div><div class="stat-value class="${st.crit>0?'critical':''}">${st.crit}</div></div>
<div class="stat"><div class="stat-label">Sources Uniques</div><div class="stat-value">${st.uniqueAttackers}</div></div>
<div class="stat"><div class="stat-label">MTTD</div><div class="stat-value">${st.mttd}m</div></div>
<div class="stat"><div class="stat-label">Taux</div><div class="stat-value">${st.alertRate}/min</div></div>

<h2>Top Attaquants</h2>
<table>
<tr><th>Adresse IP</th><th>Nombre d'alertes</th></tr>
${st.topSrc.map(([ip,c])=>`<tr><td>${esc(ip)}</td><td>${c}</td></tr>`).join("")}
</table>

<h2>MITRE ATT&CK</h2>
<table>
<tr><th>Technique</th><th>Nom</th><th>Alertes</th></tr>
${st.topMitre.map(([t,c])=>`<tr><td>${esc(t)}</td><td>${esc(MITRE_NAMES[t]||"")}</td><td>${c}</td></tr>`).join("")}
</table>

<p style="margin-top:40px;color:#64748B;font-size:12px">Généré par Snort3 SOC Dashboard</p>
</body>
</html>`;
  downloadFile(html,"rapport-soc-"+Date.now()+".html","text/html");
}

// ── MAP RENDER ───────────────────────────────────────────────
function renderMap(){
  setTimeout(()=>{
    const c=document.getElementById('worldmap');if(!c)return;
    const ctx=c.getContext('2d');
    const W=c.width=c.parentElement.clientWidth;
    const H=c.height=300;

    ctx.fillStyle='#080c18';
    ctx.fillRect(0,0,W,H);

    // Better continent outlines
    ctx.strokeStyle='rgba(255,255,255,0.08)';
    ctx.lineWidth=2;
    // Grid
    for(let i=0;i<W;i+=W/12){ctx.beginPath();ctx.moveTo(i,0);ctx.lineTo(i,H);ctx.stroke();}
    for(let i=0;i<H;i+=H/6){ctx.beginPath();ctx.moveTo(0,i);ctx.lineTo(W,i);ctx.stroke();}

    // Simplified continent shapes
    ctx.strokeStyle='rgba(6,182,212,0.15)';
    ctx.lineWidth=1;
    drawContinents(ctx,W,H);

    // Plot dots and attack lines
    const srcCount={};
    S.alerts.forEach(a=>{const ip=a.data?.src_addr;if(ip)srcCount[ip]=(srcCount[ip]||0)+1});

    // Target (Tokyo)
    const tx=((139.7+180)/360)*W;
    const ty=((90-35.7)/180)*H;

    // Draw attack lines
    ctx.globalAlpha=0.3;
    Object.entries(S.geoData).forEach(([ip,geo])=>{
      const x=((geo.lng+180)/360)*W;
      const y=((90-geo.lat)/180)*H;
      const count=srcCount[ip]||1;
      const color=count>50?"#DC2626":count>10?"#EF4444":count>3?"#F59E0B":"#3B82F6";

      ctx.strokeStyle=color;
      ctx.lineWidth=Math.min(1+count/20,3);
      ctx.beginPath();
      ctx.moveTo(x,y);
      ctx.lineTo(tx,ty);
      ctx.stroke();
    });
    ctx.globalAlpha=1;

    // Draw source dots
    Object.entries(S.geoData).forEach(([ip,geo])=>{
      const x=((geo.lng+180)/360)*W;
      const y=((90-geo.lat)/180)*H;
      const count=srcCount[ip]||1;
      const size=Math.min(3+Math.log(count)*2,12);
      const sev=count>50?"#DC2626":count>10?"#EF4444":count>3?"#F59E0B":"#3B82F6";

      // Pulsing glow
      const grad=ctx.createRadialGradient(x,y,0,x,y,size*3);
      grad.addColorStop(0,sev+'88');
      grad.addColorStop(1,sev+'00');
      ctx.fillStyle=grad;
      ctx.beginPath();
      ctx.arc(x,y,size*3,0,Math.PI*2);
      ctx.fill();

      // Dot
      ctx.fillStyle=sev;
      ctx.beginPath();
      ctx.arc(x,y,size,0,Math.PI*2);
      ctx.fill();

      // Country label for top 5
      if(count>10){
        ctx.fillStyle='#fff';
        ctx.font='bold 10px Inter';
        ctx.fillText((geo.code||'')+" ("+count+")",x+size+4,y+4);
      }
    });

    // Target marker
    ctx.fillStyle='#06B6D4';
    ctx.beginPath();
    ctx.arc(tx,ty,6,0,Math.PI*2);
    ctx.fill();
    ctx.strokeStyle='#06B6D4';
    ctx.lineWidth=2;
    ctx.beginPath();
    ctx.arc(tx,ty,12,0,Math.PI*2);
    ctx.stroke();
    ctx.fillStyle='#06B6D4';
    ctx.font='bold 11px Inter';
    ctx.fillText('TARGET (Tokyo)',tx+16,ty+4);
  },100);
}

function drawContinents(ctx,W,H){
  // Very simplified continent outlines
  // North America
  ctx.beginPath();
  ctx.moveTo(W*0.15,H*0.25);
  ctx.lineTo(W*0.25,H*0.15);
  ctx.lineTo(W*0.20,H*0.35);
  ctx.lineTo(W*0.18,H*0.45);
  ctx.lineTo(W*0.22,H*0.50);
  ctx.lineTo(W*0.15,H*0.25);
  ctx.stroke();

  // Europe
  ctx.beginPath();
  ctx.moveTo(W*0.48,H*0.28);
  ctx.lineTo(W*0.52,H*0.22);
  ctx.lineTo(W*0.55,H*0.30);
  ctx.lineTo(W*0.50,H*0.35);
  ctx.stroke();

  // Asia
  ctx.beginPath();
  ctx.moveTo(W*0.60,H*0.25);
  ctx.lineTo(W*0.75,H*0.20);
  ctx.lineTo(W*0.85,H*0.30);
  ctx.lineTo(W*0.80,H*0.40);
  ctx.lineTo(W*0.65,H*0.35);
  ctx.stroke();
}

// ── RENDER ───────────────────────────────────────────────────
function render(){
  const st=stats(S.alerts);
  const filtered=filterA();
  const now=new Date();
  const tl=st.crit>10?"CRITICAL":st.crit>3?"HIGH":st.crit>0?"MEDIUM":"LOW";
  const tc={CRITICAL:"#DC2626",HIGH:"#EF4444",MEDIUM:"#F59E0B",LOW:"#10B981"};

  // Country summary
  const countries={};
  S.alerts.forEach(a=>{const g=S.geoData[a.data?.src_addr];if(g)countries[g.country]=(countries[g.country]||0)+1});
  const topCountries=Object.entries(countries).sort((a,b)=>b[1]-a[1]).slice(0,6);

  // Get most recent critical alert message
  const lastCrit=S.alerts.find(a=>getSev(a.rule?.level||0)==="critical");
  const threatMsg=lastCrit?(lastCrit.data?.msg||"Menace critique détectée").substring(0,80):"Aucune menace critique";

  document.getElementById("app").innerHTML=`
    ${S.showConfig?renderCfg():""}
    ${S.detailAlert?renderDetailPanel(S.detailAlert):""}

    <header class="header">
      <div class="header-left">
        <div class="logo">🛡️</div>
        <div>
          <h1>SNORT<span>3</span> SOC</h1>
          <div class="header-sub">Security Operations Center</div>
        </div>
      </div>
      <div class="header-right">
        <div class="threat-pill" style="background:${tc[tl]}12;border:1px solid ${tc[tl]}33;color:${tc[tl]}">
          <div style="width:6px;height:6px;border-radius:50%;background:${tc[tl]};${tl==='CRITICAL'?'animation:pulse 1s ease infinite':''}"></div>
          ${tl}
        </div>
        <div>
          <div class="clock-date">${now.toLocaleDateString("fr-FR",{weekday:"short",day:"numeric",month:"short",year:"numeric"})}</div>
          <div class="clock-time">${now.toLocaleTimeString("fr-FR")}</div>
          <div style="font-size:8px;color:var(--dim);text-align:right;margin-top:2px">${timeSince(S.lastUpdate)} ago</div>
        </div>
        <div class="status-badge" style="background:${S.connected?"rgba(16,185,129,.06)":"rgba(245,158,11,.06)"};border:1px solid ${S.connected?"rgba(16,185,129,.15)":"rgba(245,158,11,.15)"}" onclick="S.showConfig=true;render()">
          <div class="status-dot ${S.connected?'live':''}" style="background:${S.connected?"#10B981":"#F59E0B"};box-shadow:0 0 8px ${S.connected?"#10B981":"#F59E0B"}"></div>
          <span class="status-label" style="color:${S.connected?"#10B981":"#F59E0B"}">${S.connected?"LIVE":"OFFLINE"}</span>
        </div>
      </div>
    </header>

    <div class="container">
      <!-- TABS -->
      <div class="tabs">
        <button class="tab ${S.tab==='snort'?'active':''}" onclick="S.tab='snort';render()">🐷 Snort IDS</button>
        <button class="tab ${S.tab==='windows'?'active':''}" onclick="S.tab='windows';render()">🪟 Windows</button>
        <button class="tab ${S.tab==='map'?'active':''}" onclick="S.tab='map';if(!S.mapReady)resolveGeo();render();renderMap()">🌍 Carte mondiale</button>
      </div>

      ${S.tab==='snort'?renderSnort(st,filtered,tc,tl,threatMsg):''}
      ${S.tab==='windows'?renderWindows():''}
      ${S.tab==='map'?renderMapTab(st,topCountries):''}

      <div class="footer">
        <span>Snort 3.10.2 · Wazuh 4.14.3 · OpenSearch · ${S.alerts.length} events IDS · ${S.winAlerts.length} events Windows · TFE SOC</span>
        <span>snort-ids (192.168.0.1) → Wazuh (192.168.0.2) → Dashboard · 🔊 ${S.soundEnabled?'ON':'OFF'} <button onclick="S.soundEnabled=!S.soundEnabled;render()" style="border:none;background:none;color:var(--cyan);cursor:pointer;font-size:10px">Toggle</button></span>
      </div>
    </div>`;

  if(S.tab==='map')renderMap();
}

function renderSnort(st,filtered,tc,tl,threatMsg){
  const mx=Math.max(...Object.values(st.cats),1);
  const mxS=st.topSrc.length?st.topSrc[0][1]:1;
  const maxH=Math.max(...Object.values(st.hourly),1);
  const totalProto=st.proto.TCP+st.proto.UDP+st.proto.ICMP||1;
  const blocked=getBlockedIPs();

  // Trend calculation
  const today=st.last7Days[6]?.count||0;
  const yesterday=st.last7Days[5]?.count||1;
  const trendPct=((today-yesterday)/yesterday*100).toFixed(0);
  const trendUp=today>yesterday;

  return `
    <!-- THREAT BANNER -->
    <div class="threat-banner ${st.crit===0?'safe':''}">
      <div class="threat-info">
        <span style="font-size:18px">${st.crit>0?'🚨':'🛡️'}</span>
        <div>
          <div class="threat-text" style="color:${st.crit>0?'#EF4444':'#10B981'}">${threatMsg}</div>
          <div style="font-size:9px;color:var(--dim);margin-top:2px">${st.total} événements · ${st.topSrc.length} sources · ${Object.keys(S.geoData).length} géolocalisées</div>
        </div>
      </div>
      <div class="threat-count" style="color:${st.crit>0?'#EF4444':'#10B981'}">${st.crit}</div>
    </div>

    <!-- SOC OVERVIEW PANEL -->
    <div class="soc-overview">
      <div class="soc-metric">
        <div class="soc-metric-label">⏱️ MTTD</div>
        <div class="soc-metric-value">${st.mttd}<span style="font-size:12px;color:var(--dim)">min</span></div>
        <div class="soc-metric-sub">Mean Time To Detect</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">📊 Taux d'alertes</div>
        <div class="soc-metric-value">${st.alertRate}<span style="font-size:12px;color:var(--dim)">/min</span></div>
        <div class="soc-metric-sub">Dernières 50 alertes</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">👥 Attaquants uniques</div>
        <div class="soc-metric-value">${st.uniqueAttackers}</div>
        <div class="soc-metric-sub">Dernières 24 heures</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">🎯 Port le plus ciblé</div>
        <div class="soc-metric-value">${st.topPort?st.topPort.port:'--'}<span style="font-size:12px;color:var(--dim)">${st.topPort?'/'+st.topPort.service:''}</span></div>
        <div class="soc-metric-sub">${st.topPort?st.topPort.count+' attaques':'Aucune donnée'}</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">📡 Distribution protocoles</div>
        <div class="soc-metric-value" style="font-size:14px;color:var(--text)">
          TCP ${Math.round(st.proto.TCP/totalProto*100)}% · UDP ${Math.round(st.proto.UDP/totalProto*100)}% · ICMP ${Math.round(st.proto.ICMP/totalProto*100)}%
        </div>
        <div class="proto-bar">
          <div class="proto-segment" style="width:${st.proto.TCP/totalProto*100}%;background:#3B82F6"></div>
          <div class="proto-segment" style="width:${st.proto.UDP/totalProto*100}%;background:#F59E0B"></div>
          <div class="proto-segment" style="width:${st.proto.ICMP/totalProto*100}%;background:#8B5CF6"></div>
        </div>
      </div>
    </div>

    <!-- STAT CARDS -->
    <div class="stat-cards">
      <div class="stat-card" style="background:linear-gradient(135deg,rgba(6,182,212,.08),rgba(6,182,212,.02));border-color:rgba(6,182,212,.1)">
        <div class="stat-label">Total</div>
        <div class="stat-value" style="color:var(--cyan)">${st.total}</div>
        <div class="stat-pct">${S.connected?'⟳ Live 15s':'○ Offline'}</div>
      </div>
      ${Object.entries(CATS).map(([k,c])=>`
        <div class="stat-card ${S.filter===k?'active':''}" style="background:linear-gradient(135deg,${c.color}10,${c.color}04);border-color:${c.color}15" onclick="S.filter=S.filter==='${k}'?'all':'${k}';S.mitreFilter=null;render()">
          <div class="stat-top"><span class="stat-label">${c.label}</span><span class="stat-icon">${c.icon}</span></div>
          <div class="stat-value" style="color:${c.color}">${st.cats[k]||0}</div>
          <div class="stat-pct">${((st.cats[k]||0)/Math.max(st.total,1)*100).toFixed(1)}%</div>
        </div>`).join("")}
    </div>

    <!-- TIMELINE & TRENDS -->
    <div class="grid-3">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📅</span>Timeline 7 jours</h3>
        <div class="timeline-chart">
          ${st.last7Days.map(d=>{const max=Math.max(...st.last7Days.map(x=>x.count),1);return`<div class="timeline-bar" style="height:${Math.max((d.count/max)*100,2)}%;background:${d.count>max*.7?'var(--red)':d.count>max*.4?'var(--yellow)':'var(--cyan)'}" data-tooltip="${d.label}: ${d.count}"></div>`}).join("")}
        </div>
        <div class="timeline-labels">
          ${st.last7Days.map((d,i)=>i%2===0?`<span>${d.label.split(' ')[0]}</span>`:'').join("")}
        </div>
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🕐</span>Alertes / Heure</h3>
        <div class="timeline-chart">
          ${Array.from({length:24},(_,i)=>{const v=st.hourly[i]||0;return`<div class="timeline-bar" style="height:${Math.max((v/maxH)*100,2)}%;background:${v>maxH*.7?'var(--red)':v>maxH*.4?'var(--yellow)':'var(--blue)'}" data-tooltip="${i}h: ${v} alertes"></div>`}).join("")}
        </div>
        <div class="timeline-labels"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📈</span>Tendance</h3>
        <div class="trend-indicator" style="border-color:${trendUp?'rgba(239,68,68,.3)':'rgba(16,185,129,.3)'};background:${trendUp?'rgba(239,68,68,.08)':'rgba(16,185,129,.08)'}">
          <div class="trend-arrow" style="color:${trendUp?'var(--red)':'var(--green)'}"> ${trendUp?'↗':'↘'}</div>
          <div>
            <div class="trend-text">Aujourd'hui vs hier</div>
            <div class="trend-value" style="color:${trendUp?'var(--red)':'var(--green)'}">
              ${trendUp?'+':''}${trendPct}%
            </div>
          </div>
        </div>
        <div style="margin-top:12px;font-size:10px;color:var(--muted)">Aujourd'hui: ${today} · Hier: ${yesterday}</div>
      </div>
    </div>

    <!-- MITRE HEATMAP & ACTIVE RESPONSE -->
    <div class="grid-2">
      <div class="card" style="grid-column:span 1">
        <h3 class="card-title"><span class="card-title-icon">⚔️</span>MITRE ATT&CK Heatmap ${S.mitreFilter?'<span style="color:var(--cyan);margin-left:8px">Filtré: '+esc(S.mitreFilter)+'</span> <button onclick="S.mitreFilter=null;render()" style="border:none;background:rgba(255,255,255,.05);color:var(--cyan);cursor:pointer;padding:2px 6px;border-radius:3px;font-size:9px">✕</button>':''}</h3>
        ${renderMITREHeatmap(st.mitreC)}
      </div>
      <div class="card" style="grid-column:span 1">
        <h3 class="card-title"><span class="card-title-icon">🚫</span>Active Response — IPs bloquées (${blocked.length})</h3>
        ${blocked.length===0?'<div class="empty-state">Aucune IP bloquée actuellement</div>':blocked.map(b=>`
          <div class="response-item">
            <div class="response-ip">${safeIP(b.ip)}</div>
            <div class="response-reason">${esc(b.reason.substring(0,50))} · SID ${safeSid(b.sid)}</div>
            <div class="response-time">
              <div class="response-badge active">${Math.floor(b.remaining)}s</div>
              <div style="font-size:8px;color:var(--dim);margin-top:2px">${formatTime(b.timestamp)}</div>
            </div>
          </div>`).join("")}
        ${blocked.length>0?'<div style="margin-top:8px;font-size:9px;color:var(--dim)">Auto-unblock après 300 secondes</div>':''}
      </div>
    </div>

    <!-- TOP SOURCES & FEED -->
    <div class="grid-2">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🌍</span>Top Attaquants</h3>
        ${st.topSrc.map(([ip,count],i)=>{const g=S.geoData[ip];return`<div class="bar-row"><div class="bar-header"><span class="bar-label" style="${i===0?'color:#EF4444;font-weight:600':''}">${i===0?'⚠ ':''}${safeIP(ip)} ${g?'<span style="color:var(--dim);font-size:9px">'+esc(g.country)+'</span>':''}</span><span class="bar-count" style="color:var(--dim)">${count}</span></div><div class="bar-track"><div class="bar-fill" style="width:${(count/mxS)*100}%;background:${i===0?'var(--red)':'var(--blue)'}"></div></div></div>`}).join("")}
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon" style="${S.connected?'animation:pulse 2s ease infinite':''}">📡</span>Flux temps réel</h3>
        ${S.alerts.slice(0,7).map((a,i)=>{const sv=getSev(a.rule?.level||0);const cat=getCat(a.data?.msg);const c=CATS[cat]||{color:'#6B7280',icon:'📋'};const sc=SEVS[sv];const mt=getMitre(a.data?.sid);return`<div class="feed-item ${sv}" style="animation:slideIn .3s ease ${i*.04}s both"><div class="feed-dot" style="background:${sc.color}"></div><span class="feed-time">${formatTime(a.timestamp)}</span><span style="font-size:12px">${c.icon}</span><span class="feed-msg">${safeMsg(a.data?.msg)} ${mt?'<span class="mitre-tag" onclick="S.mitreFilter=\''+mt+'\';render()">'+esc(mt)+'</span>':''}</span><span class="feed-src">${safeIP(a.data?.src_addr)}</span></div>`}).join("")}
        ${S.alerts.length===0?'<div class="empty-state">Connectez OpenSearch</div>':''}
      </div>
    </div>

    <!-- FILTER & EXPORT -->
    <div class="filter-bar">
      <div class="search-box"><span class="search-icon">⌕</span><input class="search-input" type="text" placeholder="IP, message, SID, MITRE..." value="${S.search}" oninput="S.search=this.value;render()"></div>
      <button class="filter-btn ${S.filter==='all'?'active':''}" onclick="S.filter='all';S.mitreFilter=null;render()">Tout</button>
      ${Object.entries(CATS).map(([k,v])=>`<button class="filter-btn ${S.filter===k?'active':''}" onclick="S.filter='${k}';S.mitreFilter=null;render()">${v.icon} ${v.label}</button>`).join("")}
      <button class="sort-btn" onclick="S.sortDir=S.sortDir==='desc'?'asc':'desc';render()">${S.sortDir==="desc"?"↓ Récent":"↑ Ancien"}</button>
      <button class="export-btn" onclick="exportCSV()">📄 CSV</button>
      <button class="export-btn" onclick="exportJSON()">📋 JSON</button>
      <button class="export-btn" onclick="generateReport()">📊 Rapport</button>
    </div>

    <!-- TABLE -->
    <div class="table-wrap">
      <div class="table-header">
        <span onclick="S.sortDir=S.sortDir==='desc'?'asc':'desc';render()">Heure</span>
        <span>Niveau</span>
        <span>Incident</span>
        <span>Source</span>
        <span>Destination</span>
        <span>Port</span>
        <span>Proto</span>
      </div>
      <div class="table-body">
        ${filtered.length===0?'<div class="empty-state">Aucun événement</div>':filtered.slice(0,150).map((a,i)=>{const cat=getCat(a.data?.msg);const c=CATS[cat]||{color:'#6B7280',icon:'📋'};const sv=getSev(a.rule?.level||0);const sc=SEVS[sv];const mt=getMitre(a.data?.sid);const g=S.geoData[a.data?.src_addr];return`<div class="table-row ${sv==='critical'?'crit-row':''}" style="animation:fadeIn .15s ease ${Math.min(i*.01,.4)}s both" onclick="S.detailAlert=${i};render()"><span class="cell-time">${formatTime(a.timestamp)}</span><span class="cell-sev" style="background:${sc.color}12;color:${sc.color}">${a.rule?.level||'?'}</span><div class="cell-msg"><div class="cell-msg-text"><span style="color:${c.color};margin-right:4px">${c.icon}</span>${safeMsg(a.data?.msg||a.rule?.description)}</div><div class="cell-msg-sub">SID ${safeSid(a.data?.sid)} ${mt?'· <span class="mitre-tag" onclick="event.stopPropagation();S.mitreFilter=\''+mt+'\';render()">'+esc(mt)+'</span>':''} ${g?'· '+esc(g.code):''}</div></div><span class="cell-ip">${safeIP(a.data?.src_addr)}</span><span class="cell-ip dim">${safeIP(a.data?.dst_addr)}</span><span class="cell-port">${safePort(a.data?.dst_port)}</span><span class="cell-proto">${safeProto(a.data?.proto)}</span></div>`}).join("")}
      </div>
    </div>`;
}

function renderMITREHeatmap(mitreC){
  let html='<div class="mitre-heatmap">';
  Object.entries(MITRE_TACTICS).forEach(([tactic,data])=>{
    const techniques=data.techniques.filter(t=>mitreC[t]||false);
    if(techniques.length===0)return;
    const maxCount=Math.max(...techniques.map(t=>mitreC[t]||0),1);
    html+=`<div class="mitre-tactic">
      <div class="mitre-tactic-title" style="color:${data.color}">▸ ${esc(tactic)}</div>
      <div class="mitre-techniques">
        ${techniques.map(t=>{
          const count=mitreC[t]||0;
          const intensity=count/maxCount;
          const bg=`rgba(139,92,246,${0.1+intensity*0.6})`;
          return`<div class="mitre-cell ${S.mitreFilter===t?'active':''}" style="background:${bg}" onclick="S.mitreFilter=S.mitreFilter==='${t}'?null:'${t}';render()">
            <span class="mitre-cell-id">${esc(t)}</span>
            <span class="mitre-cell-count">${count}</span>
            <span class="mitre-cell-name">${esc((MITRE_NAMES[t]||'').substring(0,15))}</span>
          </div>`;
        }).join("")}
      </div>
    </div>`;
  });
  html+='</div>';
  return html;
}

function renderDetailPanel(idx){
  const a=filterA()[idx];
  if(!a)return'';
  const sv=getSev(a.rule?.level||0);
  const sc=SEVS[sv];
  const mt=getMitre(a.data?.sid);
  const g=S.geoData[a.data?.src_addr];
  const isBlocked=(a.rule?.description||"").includes("BLOCKED");

  return `
    <div class="detail-overlay" onclick="S.detailAlert=null;render()"></div>
    <div class="detail-panel">
      <div class="detail-header">
        <div class="detail-title">📋 Détail de l'alerte</div>
        <button class="detail-close" onclick="S.detailAlert=null;render()">×</button>
      </div>
      <div class="detail-body">
        <div class="detail-section">
          <div class="detail-section-title">Informations générales</div>
          ${isBlocked?'<div class="detail-badge blocked">🚫 IP BLOQUÉE PAR ACTIVE RESPONSE</div>':''}
          <div class="detail-field">
            <div class="detail-field-label">Timestamp</div>
            <div class="detail-field-value">${esc(a.timestamp)} (${timeSince(a.timestamp)} ago)</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Sévérité</div>
            <div class="detail-field-value"><span class="cell-sev" style="background:${sc.color}12;color:${sc.color};padding:4px 8px">${a.rule?.level||'?'} — ${sc.label}</span></div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Message</div>
            <div class="detail-field-value">${esc(a.data?.msg||a.rule?.description||'N/A')}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">SID</div>
            <div class="detail-field-value">${safeSid(a.data?.sid)}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Catégorie</div>
            <div class="detail-field-value">${esc((a.rule?.groups||[]).join(', '))}</div>
          </div>
        </div>

        ${mt?`<div class="detail-section">
          <div class="detail-section-title">MITRE ATT&CK</div>
          <div class="detail-field">
            <div class="detail-field-label">Technique</div>
            <div class="detail-field-value"><span class="mitre-tag" style="font-size:11px;padding:4px 10px">${esc(mt)}</span> ${esc(MITRE_NAMES[mt]||'')}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Description</div>
            <div class="detail-field-value">Technique de la matrice MITRE ATT&CK utilisée pour classifier cette attaque.</div>
          </div>
        </div>`:''}

        <div class="detail-section">
          <div class="detail-section-title">Réseau</div>
          <div class="detail-field">
            <div class="detail-field-label">Adresse source</div>
            <div class="detail-field-value">${safeIP(a.data?.src_addr)}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Adresse destination</div>
            <div class="detail-field-value">${safeIP(a.data?.dst_addr)}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Port destination</div>
            <div class="detail-field-value">${safePort(a.data?.dst_port)} ${PORT_SERVICES[a.data?.dst_port]?'('+PORT_SERVICES[a.data?.dst_port]+')':''}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Protocole</div>
            <div class="detail-field-value">${safeProto(a.data?.proto)}</div>
          </div>
        </div>

        ${g?`<div class="detail-section">
          <div class="detail-section-title">Géolocalisation</div>
          <div class="detail-field">
            <div class="detail-field-label">Pays</div>
            <div class="detail-field-value">${esc(g.country)} (${esc(g.code)})</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Coordonnées</div>
            <div class="detail-field-value">Lat: ${esc(String(g.lat))}, Lng: ${esc(String(g.lng))}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Organisation</div>
            <div class="detail-field-value">${esc(g.org||'N/A')}</div>
          </div>
        </div>`:''}

        <div class="detail-section">
          <div class="detail-section-title">JSON brut</div>
          <button class="detail-btn" onclick="copyToClipboard(${JSON.stringify(JSON.stringify(a))})">📋 Copier JSON</button>
          <div class="detail-json">${esc(JSON.stringify(a,null,2))}</div>
        </div>
      </div>
    </div>`;
}

function renderWindows(){
  const winStats={};
  const eventCat={Security:0,System:0,Application:0};
  const loginStats={success:0,failed:0};
  const userStats={};
  const sevs={low:0,medium:0,high:0,critical:0};

  S.winAlerts.forEach(a=>{
    const desc=a.rule?.description||'Other';
    winStats[desc]=(winStats[desc]||0)+1;
    sevs[getSev(a.rule?.level||0)]++;

    // EventID categorization
    const evtId=a.data?.win?.system?.eventID;
    const evt=WIN_EVENTS[evtId];
    if(evt){
      eventCat[evt.category]=(eventCat[evt.category]||0)+1;
      if(evtId===4624)loginStats.success++;
      if(evtId===4625)loginStats.failed++;
    }

    // User activity
    const user=a.data?.win?.system?.user||a.agent?.name||'Unknown';
    userStats[user]=(userStats[user]||0)+1;
  });

  const topWin=Object.entries(winStats).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const topUsers=Object.entries(userStats).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const maxU=topUsers.length?topUsers[0][1]:1;

  return `
    <div class="grid-3" style="margin-bottom:14px">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🪟</span>Catégories Windows</h3>
        ${Object.entries(eventCat).map(([cat,count])=>{
          const color=cat==='Security'?'#3B82F6':cat==='System'?'#F59E0B':'#10B981';
          return`<div class="bar-row"><div class="bar-header"><span class="bar-label">${esc(cat)}</span><span class="bar-count" style="color:${color}">${count}</span></div><div class="bar-track"><div class="bar-fill" style="width:${(count/Math.max(...Object.values(eventCat),1))*100}%;background:${color}"></div></div></div>`;
        }).join("")}
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🔑</span>Activité de connexion</h3>
        <div style="display:flex;gap:20px;margin-bottom:16px">
          <div style="text-align:center;flex:1">
            <div style="font-size:26px;font-weight:800;color:var(--green);font-family:var(--sans)">${loginStats.success}</div>
            <div style="font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:4px">✅ Réussis</div>
          </div>
          <div style="text-align:center;flex:1">
            <div style="font-size:26px;font-weight:800;color:var(--red);font-family:var(--sans)">${loginStats.failed}</div>
            <div style="font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:4px">❌ Échoués</div>
          </div>
        </div>
        <div style="font-size:10px;color:var(--muted)">EventID 4624/4625</div>
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📊</span>Sévérité</h3>
        ${Object.entries(SEVS).map(([k,c])=>`<div class="bar-row"><div class="bar-header"><span class="bar-label">${c.label}</span><span class="bar-count" style="color:${c.color}">${sevs[k]}</span></div><div class="bar-track"><div class="bar-fill" style="width:${(sevs[k]/Math.max(S.winAlerts.length,1))*100}%;background:${c.color}"></div></div></div>`).join("")}
      </div>
    </div>

    <div class="grid-2" style="margin-bottom:14px">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">👥</span>Activité utilisateurs</h3>
        ${topUsers.map(([user,count])=>`<div class="bar-row"><div class="bar-header"><span class="bar-label">${esc(user.substring(0,30))}</span><span class="bar-count" style="color:var(--cyan)">${count}</span></div><div class="bar-track"><div class="bar-fill" style="width:${(count/maxU)*100}%;background:var(--cyan)"></div></div></div>`).join("")}
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📋</span>Top Événements</h3>
        ${topWin.slice(0,8).map(([desc,count])=>`<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03)"><span style="font-size:10px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(desc.substring(0,50))}</span><span style="font-size:10px;color:var(--cyan);font-weight:600;margin-left:8px">${count}</span></div>`).join("")}
      </div>
    </div>

    <!-- Windows alerts table -->
    <div class="table-wrap">
      <div class="table-header" style="grid-template-columns:85px 56px 1fr 130px 80px"><span>Heure</span><span>Niveau</span><span>Description</span><span>Agent</span><span>Rule ID</span></div>
      <div class="table-body">
        ${S.winAlerts.length===0?'<div class="empty-state">Aucun événement Windows</div>':S.winAlerts.slice(0,100).map((a,i)=>{const sv=getSev(a.rule?.level||0);const sc=SEVS[sv];return`<div class="table-row" style="grid-template-columns:85px 56px 1fr 130px 80px;animation:fadeIn .15s ease ${Math.min(i*.01,.3)}s both"><span class="cell-time">${formatTime(a.timestamp)}</span><span class="cell-sev" style="background:${sc.color}12;color:${sc.color}">${a.rule?.level||'?'}</span><div class="cell-msg"><div class="cell-msg-text">${esc((a.rule?.description||'').substring(0,80))}</div><div class="cell-msg-sub">${esc((a.rule?.groups||[]).join(', ').substring(0,50))}</div></div><span class="cell-ip">${esc(a.agent?.name||'?')}</span><span style="font-size:10px;color:var(--dim);text-align:center">${esc(String(a.rule?.id||'?'))}</span></div>`}).join("")}
      </div>
    </div>`;
}

function renderMapTab(st,topCountries){
  const mxC=topCountries.length?topCountries[0][1]:1;
  const countries=Object.keys(S.geoData).length;
  const totalAttacks=st.total;
  const mostActive=topCountries[0]?topCountries[0][0]:'N/A';

  return `
    <div class="grid-2">
      <div class="card" style="grid-column:span 2">
        <h3 class="card-title"><span class="card-title-icon">🗺️</span>Carte des attaques — Géolocalisation des sources</h3>
        <div class="map-container">
          <canvas id="worldmap"></canvas>
          <div class="map-stats-overlay">
            <div class="map-stats-item">Total:<span class="map-stats-value">${totalAttacks}</span></div>
            <div class="map-stats-item">Pays:<span class="map-stats-value">${countries}</span></div>
            <div class="map-stats-item">Plus actif:<span class="map-stats-value">${esc(mostActive.substring(0,12))}</span></div>
          </div>
        </div>
        <div class="map-legend">
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--cyan)"></div>Serveur cible (Tokyo)</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--blue)"></div>Faible (1-3)</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--yellow)"></div>Moyen (4-10)</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--red)"></div>Élevé (11-50)</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--crimson)"></div>Critique (50+)</div>
        </div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🏴</span>Top Pays attaquants</h3>
        ${topCountries.map(([country,count],i)=>`<div class="bar-row"><div class="bar-header"><span class="bar-label" style="${i===0?'color:var(--red);font-weight:600':''}">${esc(country)}</span><span class="bar-count" style="color:var(--dim)">${count}</span></div><div class="bar-track"><div class="bar-fill" style="width:${(count/mxC)*100}%;background:${i===0?'var(--red)':'var(--blue)'}"></div></div></div>`).join("")}
        ${topCountries.length===0?'<div style="color:var(--dark);font-size:10px">Géolocalisation en cours...</div>':''}
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📍</span>IPs géolocalisées</h3>
        ${Object.entries(S.geoData).slice(0,8).map(([ip,g])=>`<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:10px"><span style="color:var(--muted)">${safeIP(ip)}</span><span style="color:var(--dim)">${esc(g.country)} · ${esc((g.org||'').substring(0,20))}</span></div>`).join("")}
        ${Object.keys(S.geoData).length===0?'<div style="color:var(--dark);font-size:10px">Connectez OpenSearch pour géolocaliser</div>':''}
      </div>
    </div>`;
}

function renderCfg(){
  return `<div class="modal-overlay" onclick="if(event.target===this){S.showConfig=false;render()}"><div class="modal"><div class="modal-head"><h2>⚙ OpenSearch</h2><button class="modal-close" onclick="S.showConfig=false;render()">×</button></div>
    ${S.connected?'<div class="ok-badge">● Connecté · '+S.alerts.length+' alertes Snort · '+S.winAlerts.length+' alertes Windows</div>':''}
    ${S.error?'<div class="err-badge">✗ '+esc(S.error)+'</div>':''}
    <div class="modal-field"><label class="modal-label">URL OpenSearch</label><input class="modal-input" value="${S.config.url}" oninput="S.config.url=this.value"></div>
    <div class="modal-field"><label class="modal-label">Utilisateur</label><input class="modal-input" value="${S.config.username}" oninput="S.config.username=this.value"></div>
    <div class="modal-field"><label class="modal-label">Mot de passe</label><input class="modal-input" type="password" value="${S.config.password}" oninput="S.config.password=this.value"></div>
    <div class="modal-btns"><button class="btn-primary" onclick="connect()">Connecter</button><button class="btn-secondary" onclick="S.showConfig=false;render()">Annuler</button></div>
    <p class="modal-hint">Proxy Caddy → OpenSearch · Snort IDS + Windows via Wazuh agents</p>
  </div></div>`;
}

function copyToClipboard(text){
  navigator.clipboard.writeText(JSON.parse(text)).then(()=>{
    alert('JSON copié dans le presse-papiers');
  }).catch(()=>{
    alert('Erreur lors de la copie');
  });
}

// ── INIT ─────────────────────────────────────────────────────
setInterval(()=>{
  const cd=document.querySelector(".clock-date");
  const ct=document.querySelector(".clock-time");
  if(cd&&ct){
    const n=new Date();
    cd.textContent=n.toLocaleDateString("fr-FR",{weekday:"short",day:"numeric",month:"short",year:"numeric"});
    ct.textContent=n.toLocaleTimeString("fr-FR");
  }
},1000);

render();
