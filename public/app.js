"use strict";
const $=id=>document.getElementById(id);
const state={connected:false,eventSource:null,poller:null,noticeTimer:null};
let pairingToken="";
try{
 const u=new URL(window.location.href);
 pairingToken=u.searchParams.get("pair")||"";
 if(pairingToken){u.searchParams.delete("pair");window.history.replaceState(null,"",u.pathname+u.search+u.hash);}
}catch{}
async function finishPair(){
 if(!/^[a-f0-9]{48}$/.test(pairingToken))return;
 const pending=pairingToken;pairingToken="";
 try{await api("/api/bot/pair","POST",{pair:pending});notice("✅ Telegram bot himoyasi akkauntingizga ulandi.");}
 catch(e){notice("Botni ulash: "+e.message);}
}
async function api(url,method="GET",body){
 const opt={method,credentials:"same-origin",headers:{}};
 if(body!==undefined){opt.headers["Content-Type"]="application/json";opt.body=JSON.stringify(body);}
 const response=await fetch(url,opt);
 let result={};try{result=await response.json();}catch{}
 if(!response.ok)throw Error(result.error||"Server xatosi");
 return result;
}
function notice(message){
 $("notice").textContent=message;$("notice").classList.remove("hidden");
 clearTimeout(state.noticeTimer);state.noticeTimer=setTimeout(()=>$("notice").classList.add("hidden"),6500);
}
function buttonBusy(id,busy,text){
 const el=$(id);el.disabled=busy;if(text)el.textContent=text;
}
function riskLabel(value){return value==="high"?"YUQORI XAVF":value==="warning"?"SHUBHALI":"PAST BELGI";}
function setConnected(connected){
 state.connected=connected;
 $("disconnected-view").classList.toggle("hidden",connected);
 $("connected-view").classList.toggle("hidden",!connected);
 $("connection-chip").textContent=connected?"ULANGAN":"ULANMAGAN";
 if(!connected){
  for(const id of ["count-high","count-warning","count-low","count-total"])$(id).textContent="—";
  $("events-list").textContent="Akkaunt ulangach monitoring natijalari shu yerda paydo bo'ladi.";
  state.eventSource?.close();state.eventSource=null;
 }
}
async function refresh(){
 if(!state.connected)return;
 try{
  const [a,summary,history]=await Promise.all([api("/api/account"),api("/api/summary"),api("/api/events")]);
  $("account-name").textContent=a.displayName;
  $("account-user").textContent=a.username?"@"+a.username:(a.live?"Jonli ulangan":"Ulanish tiklanmoqda");
  $("monitoring").checked=Boolean(a.monitoring);
  $("count-high").textContent=summary.counts.high;
  $("count-warning").textContent=summary.counts.warning;
  $("count-low").textContent=summary.counts.low;
  $("count-total").textContent=summary.total;
  renderEvents(history.events);
 }catch(e){if(e.message.includes("Sessiya")||e.message.includes("Akkaunt"))setConnected(false);else notice(e.message);}
}
function renderEvents(events){
 const list=$("events-list");list.replaceChildren();
 if(!events.length){list.className="events-empty";list.textContent="Hozircha tahlil hodisalari yo'q. Yangi shaxsiy Telegram xabarlari kelganda shu yerda ko'rinadi.";return;}
 list.className="";
 for(const event of events){
  const item=document.createElement("div");item.className="event";
  const left=document.createElement("div");const head=document.createElement("b");
  head.textContent=event.type==="file"?"📎 Fayl metama'lumoti":"✉ Kiruvchi xabar";
  const small=document.createElement("small");
  const reasons=Array.isArray(event.reasons)?event.reasons.join(" · "):"";
  const time=event.createdAt?new Date(event.createdAt).toLocaleString("uz-UZ"):"";
  small.textContent=(reasons||"Qoidaviy xavf belgisi kam")+" • "+time;
  left.append(head,small);
  const badge=document.createElement("span");badge.className="pill "+event.risk;
  badge.textContent=riskLabel(event.risk)+" "+event.score+"/100";
  item.append(left,badge);list.append(item);
 }
}
function startEvents(){
 if(state.eventSource)return;
 const source=new EventSource("/api/stream");state.eventSource=source;
 source.addEventListener("risk",async event=>{
  try{const value=JSON.parse(event.data);if(value.risk==="high")notice("⚠️ Telegramda yuqori xavf belgisi aniqlangan");await refresh();}catch{}
 });
 source.onerror=()=>{};
}
async function status(){
 try{
  const s=await api("/api/connect/status");
  if(s.status==="connected"){
   clearInterval(state.poller);state.poller=null;
   setConnected(true);$("qr-block").classList.add("hidden");
   await refresh();startEvents();await finishPair();return;
  }
  if(s.status==="qr_ready"&&s.qr){
   $("qr").src=s.qr;$("qr-block").classList.remove("hidden");
   buttonBusy("connect",true,"Telegram orqali tasdiqlang");
  }else if(s.status==="error"){
   clearInterval(state.poller);state.poller=null;
   buttonBusy("connect",false,"🔒 QR orqali ulash");notice(s.error||"Ulanishda xato");
  }else if(s.status==="idle"){
   clearInterval(state.poller);state.poller=null;
   buttonBusy("connect",false,"🔒 QR orqali ulash");
  }
 }catch(e){notice(e.message);}
}
async function initialize(){
 try{
  const health=await api("/api/health");
  $("server-status").textContent=health.telegramConfigured?"● Telegram API tayyor":"● Telegram API sozlanmagan";
  $("server-status").style.color=health.telegramConfigured?"#5ff3bf":"#f1c97a";
 }catch{$("server-status").textContent="● Server ulanmagan";}
 await status();
}
$("connect").addEventListener("click",async()=>{
 if(!$("consent").checked)return notice("Avval ulanish va monitoring shartlarini tasdiqlang");
 buttonBusy("connect",true,"QR tayyorlanmoqda...");
 try{
  await api("/api/connect/start","POST",{consent:true});
  state.poller=setInterval(status,2200);await status();
 }catch(e){buttonBusy("connect",false,"🔒 QR orqali ulash");notice(e.message);}
});
$("scan").addEventListener("click",async()=>{
 const text=$("input-text").value;
 if(!text.trim())return notice("Tekshirish uchun xabar yoki havola kiriting");
 buttonBusy("scan",true,"Tekshirilmoqda...");
 try{
  const result=await api("/api/check","POST",{text});
  $("scan-result").classList.remove("hidden");
  $("scan-title").textContent=riskLabel(result.level)+" · "+result.score+"/100";
  $("scan-bar").className=result.level==="high"?"high":result.level==="warning"?"warn":"";
  $("scan-bar").style.width=result.score+"%";
  $("scan-reasons").replaceChildren();
  const reasons=result.reasons.length?result.reasons:["Aniq qoidaviy xavf belgisi topilmadi (xavfsizlik kafolati emas)"];
  for(const message of reasons){const li=document.createElement("li");li.textContent=message;$("scan-reasons").append(li);}
 }catch(e){notice(e.message);}finally{buttonBusy("scan",false,"⌕ Xavfni tahlil qilish");}
});
$("monitoring").addEventListener("change",async()=>{
 try{await api("/api/settings","POST",{monitoring:$("monitoring").checked});notice($("monitoring").checked?"Monitoring yoqildi":"Monitoring to'xtatildi");await refresh();}
 catch(e){$("monitoring").checked=!$("monitoring").checked;notice(e.message);}
});
$("logout").addEventListener("click",async()=>{
 try{await api("/api/logout","POST",{});setConnected(false);notice("Paneldan chiqdingiz");}catch(e){notice(e.message);}
});
$("disconnect").addEventListener("click",async()=>{
 if(!confirm("Telegram sessiyasi va barcha xavf tarixini o'chirishni tasdiqlaysizmi?"))return;
 try{await api("/api/account","DELETE");setConnected(false);notice("Telegram akkaunti butunlay uzildi");}catch(e){notice(e.message);}
});
$("refresh").addEventListener("click",refresh);
initialize();
