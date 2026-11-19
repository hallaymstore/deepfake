"use strict";
require("dotenv").config();
const crypto=require("node:crypto");
const path=require("node:path");
const express=require("express");
const helmet=require("helmet");
const QRCode=require("qrcode");
const {MongoClient}=require("mongodb");
const {TelegramClient}=require("teleproto");
const {StringSession}=require("teleproto/sessions");
const {analyse,encrypt,hash}=require("./analyzer");
const {createTelegramEngine}=require("./telegram");
const {createSecurityBot}=require("./security-bot");

const mongoUri=process.env.MONGODB_URI||"";
const dbName=process.env.MONGODB_DB||"hallaym_shield_deepfake";
const key=process.env.SESSION_ENCRYPTION_KEY||"";
const apiId=Number(process.env.TELEGRAM_API_ID||0);
const apiHash=process.env.TELEGRAM_API_HASH||"";
const telegramReady=Number.isSafeInteger(apiId)&&apiId>0&&/^[a-f0-9]{32}$/i.test(apiHash);
const configured=Boolean(mongoUri.startsWith("mongodb")&&/^[a-f0-9]{64}$/i.test(key));

const isProd=process.env.NODE_ENV==="production";
const origin=process.env.PUBLIC_ORIGIN||"http://localhost:3000";
if(isProd&&!origin.startsWith("https://"))throw Error("HTTPS PUBLIC_ORIGIN required in production");

const app=express();
app.disable("x-powered-by");
app.set("trust proxy",process.env.TRUST_PROXY==="true"?1:false);
app.use(helmet({contentSecurityPolicy:{directives:{
 defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'","data:"],
 connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"],upgradeInsecureRequests:isProd?[]:null
}}}));
app.use(express.json({limit:"16kb"}));
app.use(express.static(path.join(__dirname,"../public")));
app.use("/api",(req,res,next)=>{
 res.set("Cache-Control","no-store");
 if(!["GET","HEAD"].includes(req.method)){
  if(req.headers.origin&&req.headers.origin!==origin)return res.status(403).json({error:"So'rov manbasi ruxsat etilmagan"});
  if(req.headers["sec-fetch-site"]==="cross-site")return res.status(403).json({error:"Ruxsat etilmagan"});
 }
 next();
});
const attempt=new Map(),guests=new Map(),streams=new Map();
const guestCookie="shield_guest",authCookie="shield_auth";
const now=()=>Date.now();
const limit=100;
app.use("/api",(req,res,next)=>{
 const ip=req.ip;const current=now();let item=attempt.get(ip);
 if(!item||current-item.at>60000)item={at:current,n:0};
 item.n++;attempt.set(ip,item);
 if(item.n>limit)return res.status(429).json({error:"So'rovlar limiti oshdi"});
 next();
});
setInterval(()=>{
 for(const [id,s] of guests){if(now()-s.createdAt>180000){
   s.controller?.abort();s.client?.disconnect().catch(()=>{});guests.delete(id);
 }}
 for(const [id,s] of attempt)if(now()-s.at>60000)attempt.delete(id);
},30000).unref();
function getCookie(req,name){
 const part=(req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
 return part?part.slice(name.length+1):"";
}
function cookie(res,name,value,maxAge){res.cookie(name,value,{httpOnly:true,secure:isProd,sameSite:"strict",maxAge,path:"/"});}
function clear(res,name){res.clearCookie(name,{httpOnly:true,secure:isProd,sameSite:"strict",path:"/"});}
function error(res,status,message){return res.status(status).json({error:message});}
let db,engine,securityBot;
async function signedIn(req,res,next){
 if(!db)return error(res,503,"MongoDB sozlanmagan");
 const token=getCookie(req,authCookie);
 if(!/^[a-f0-9]{64}$/.test(token))return error(res,401,"Avval Telegram akkauntni ulang");
 const session=await db.collection("webSessions").findOne({tokenHash:hash(token),expiresAt:{$gt:new Date()}});
 if(!session)return error(res,401,"Sessiya muddati tugagan");
 req.accountId=session.accountId;req.sessionHash=session.tokenHash;next();
}
function broadcast(id,event){
 if(securityBot&&event.risk!=="low")securityBot.notify(id,event).catch(e=>console.error("Bot alert:",e?.message));
 const set=streams.get(id);if(!set)return;
 for(const res of set){try{res.write("event: risk\ndata: "+JSON.stringify(event)+"\n\n");}
 catch{set.delete(res);}}
}
app.get("/api/health",(req,res)=>res.json({
 ok:true,service:"hallaym-shield",database:dbName,telegramConfigured:telegramReady&&configured,setupRequired:!configured||!telegramReady,
 scanner:"metadata-only",botEnabled:Boolean(securityBot),mode:"mvp"
}));
app.post("/api/check",(req,res)=>{
 const txt=String(req.body?.text||"").slice(0,10000);
 if(!txt.trim())return error(res,400,"Tekshirish uchun matn kiriting");
 res.json({...analyse(txt),method:"rule-based",note:"AI yoki antivirus xulosasi emas"});
});
app.post("/api/connect/start",async(req,res)=>{
 if(!configured||!telegramReady)return error(res,503,"Telegram va MongoDB API kalitlari Render Environment sozlamalarida to'ldirilishi kerak");
 if(req.body?.consent!==true)return error(res,400,"Shaxsiy akkauntga kirish huquqini aniq tasdiqlang");
 let guest=getCookie(req,guestCookie);
 if(!/^[a-f0-9]{64}$/.test(guest))guest=crypto.randomBytes(32).toString("hex");
 const id=hash(guest),prev=guests.get(id);
 if(prev&&now()-prev.createdAt<150000&&prev.status!=="error"){
  cookie(res,guestCookie,guest,180000);
  return res.json({status:prev.status,qr:prev.qr||null});
 }
 prev?.controller?.abort();prev?.client?.disconnect().catch(()=>{});
 const state={status:"connecting",createdAt:now(),qr:null,client:null,controller:new AbortController()};
 guests.set(id,state);
 cookie(res,guestCookie,guest,180000);
 (async()=>{
  const client=new TelegramClient(new StringSession(""),apiId,apiHash,{connectionRetries:5});
  state.client=client;
  try{
   await client.connect();
   const user=await client.signInUserWithQrCode({apiId,apiHash},{
    abortSignal:state.controller.signal,
    qrCode:async({token})=>{
     if(state.controller.signal.aborted)return;
     state.qr=await QRCode.toDataURL("tg://login?token="+token.toString("base64url"),{width:260,margin:1});
     state.status="qr_ready";
    },
    password:async()=>{throw Error("2FA_REQUIRED");},
    onError:()=>true
   });
   if(state.controller.signal.aborted)return;
   const telegramId=String(user.id);
   const existing=await engine.accounts.findOne({telegramId});
   const account={
    telegramId,displayName:[user.firstName,user.lastName].filter(Boolean).join(" ")||"Telegram user",
    username:user.username||null,sessionEncrypted:encrypt(client.session.save(),key),
    monitoring:true,consentedAt:new Date(),authExpired:false,updatedAt:new Date(),
    firstConnectedAt:existing?.firstConnectedAt||new Date()
   };
   await engine.accounts.updateOne({telegramId},{$set:account},{upsert:true});
   await engine.activate(account,client);
   state.accountId=telegramId;state.qr=null;state.client=null;state.status="authorized";
  }catch(e){
   state.status="error";
   state.error=String(e?.message||"").includes("2FA")?
    "Akkauntda ikki bosqichli himoya bor; ushbu MVP 2FA parolini yig'maydi.":
    "Telegram ulanishida xato. Qayta urinib ko'ring.";
   await client.disconnect().catch(()=>{});
  }
 })().catch(e=>console.error("Telegram authentication task:",e?.message));
 res.json({status:"connecting"});
});
app.get("/api/connect/status",async(req,res)=>{
 if(!db)return res.json({status:"idle",telegramConfigured:false,setupRequired:true});
 const token=getCookie(req,authCookie);
 if(/^[a-f0-9]{64}$/.test(token)){
  const session=await db.collection("webSessions").findOne({tokenHash:hash(token),expiresAt:{$gt:new Date()}});
  if(session)return res.json({status:"connected"});
 }
 const guest=getCookie(req,guestCookie);
 const state=/^[a-f0-9]{64}$/.test(guest)?guests.get(hash(guest)):null;
 if(!state)return res.json({status:"idle",telegramConfigured:telegramReady});
 if(state.status==="authorized"){
  const sessionToken=crypto.randomBytes(32).toString("hex");
  await db.collection("webSessions").insertOne({
   tokenHash:hash(sessionToken),accountId:state.accountId,createdAt:new Date(),
   expiresAt:new Date(now()+30*86400000)
  });
  cookie(res,authCookie,sessionToken,30*86400000);
  clear(res,guestCookie);guests.delete(hash(guest));
  return res.json({status:"connected"});
 }
 res.json({status:state.status,qr:state.qr,error:state.error||null,telegramConfigured:telegramReady});
});
app.post("/api/bot/pair",signedIn,async(req,res)=>{
 const raw=String(req.body?.pair||"");
 if(!/^[a-f0-9]{48}$/.test(raw))return error(res,400,"Ulash kodi noto'g'ri");
 const ticket=await db.collection("botLinkRequests").findOneAndDelete({
   tokenHash:hash(raw),telegramId:req.accountId,expiresAt:{$gt:new Date()}
 });
 if(!ticket)return error(res,403,"Havola muddati tugagan yoki boshqa akkaunt uchun");
 const result=await db.collection("accounts").updateOne({telegramId:req.accountId},
   {$set:{botChatId:ticket.botChatId,botLinkedAt:new Date()}});
 if(!result.matchedCount)return error(res,404,"Ulangan akkaunt topilmadi");
 res.json({ok:true});
});
app.get("/api/account",signedIn,async(req,res)=>{
 const a=await engine.accounts.findOne({telegramId:req.accountId});
 if(!a)return error(res,404,"Akkaunt topilmadi");
 res.json({telegramId:a.telegramId,displayName:a.displayName,username:a.username,
   monitoring:a.monitoring,botLinked:Boolean(a.botChatId),live:engine.active.has(req.accountId),
   scanMode:"metadata-only",authExpired:a.authExpired||false});
});
app.get("/api/events",signedIn,async(req,res)=>{
 const rows=await engine.events.find({accountId:req.accountId},
  {projection:{accountId:0,senderKey:0}}).sort({createdAt:-1}).limit(100).toArray();
 res.json({events:rows.map(x=>({...x,_id:String(x._id)}))});
});
app.get("/api/summary",signedIn,async(req,res)=>{
 const result=await engine.events.aggregate([
  {$match:{accountId:req.accountId}},{$group:{_id:"$risk",total:{$sum:1}}}
 ]).toArray();
 const counts={high:0,warning:0,low:0};
 for(const row of result)if(row._id in counts)counts[row._id]=row.total;
 res.json({counts,total:counts.high+counts.warning+counts.low});
});
app.get("/api/stream",signedIn,(req,res)=>{
 res.set({"Content-Type":"text/event-stream","Cache-Control":"no-store","Connection":"keep-alive","X-Accel-Buffering":"no"});
 res.flushHeaders();res.write(": connected\n\n");
 const id=req.accountId,clients=streams.get(id)||new Set();clients.add(res);streams.set(id,clients);
 const beat=setInterval(()=>{try{res.write(": heartbeat\n\n");}catch{}},25000);
 req.on("close",()=>{clearInterval(beat);clients.delete(res);if(!clients.size)streams.delete(id);});
});
app.post("/api/settings",signedIn,async(req,res)=>{
 if(typeof req.body?.monitoring!=="boolean")return error(res,400,"monitoring true/false bo'lishi kerak");
 await engine.accounts.updateOne({telegramId:req.accountId},
  {$set:{monitoring:req.body.monitoring,updatedAt:new Date()}});
 if(req.body.monitoring){
  if(!telegramReady)return error(res,503,"Telegram API kalitlari sozlanmagan");
  await engine.reload(req.accountId);
 }else await engine.pause(req.accountId);
 res.json({ok:true});
});
app.post("/api/logout",signedIn,async(req,res)=>{
 await db.collection("webSessions").deleteOne({tokenHash:req.sessionHash});
 clear(res,authCookie);res.json({ok:true});
});
app.delete("/api/account",signedIn,async(req,res)=>{
 await engine.revoke(req.accountId);
 await Promise.all([
  engine.accounts.deleteOne({telegramId:req.accountId}),
  engine.events.deleteMany({accountId:req.accountId}),
  db.collection("webSessions").deleteMany({accountId:req.accountId})
 ]);
 clear(res,authCookie);res.json({ok:true});
});
app.use("/api",(err,req,res,next)=>{
 console.error("API error:",err?.message||"unknown");error(res,500,"Server xatosi");
});

async function main(){
 const client=new MongoClient(mongoUri,{serverSelectionTimeoutMS:18000,maxPoolSize:20});
 await client.connect();
 db=client.db(dbName);
 await Promise.all([
  db.collection("accounts").createIndex({telegramId:1},{unique:true}),
  db.collection("riskEvents").createIndex({accountId:1,createdAt:-1}),
  db.collection("riskEvents").createIndex({expiresAt:1},{expireAfterSeconds:0}),
  db.collection("webSessions").createIndex({tokenHash:1},{unique:true}),
  db.collection("webSessions").createIndex({expiresAt:1},{expireAfterSeconds:0})
 ]);
 engine=createTelegramEngine({db,apiId,apiHash,key,retentionDays:process.env.EVENT_RETENTION_DAYS||7,onRisk:broadcast});
 if(telegramReady)await engine.restore();
 else console.warn("Telegram API variables missing; QR login disabled until configured");
 if(process.env.TELEGRAM_BOT_TOKEN){
  try{securityBot=await createSecurityBot({db,origin,engine,token:process.env.TELEGRAM_BOT_TOKEN});}
  catch(err){console.error("Security bot unavailable:",err.message);}
 }
 const port=Number(process.env.PORT||3000);
 const server=app.listen(port,"0.0.0.0",()=>console.log("HALLAYM SHIELD listening on",port));
 const stop=async()=>{server.close();securityBot?.stop();await engine.stopAll();await client.close();process.exit(0);};
 process.once("SIGINT",stop);process.once("SIGTERM",stop);
}
if(require.main===module){
 if(!configured){
  const port=Number(process.env.PORT||3000);
  app.listen(port,"0.0.0.0",()=>console.warn("HALLAYM SHIELD setup mode: MongoDB and encryption key are not configured"));
 }else{
  main().catch(e=>{
   console.error("Database startup failed:",e.message);
   db=null;engine=null;
   const port=Number(process.env.PORT||3000);
   app.listen(port,"0.0.0.0",()=>console.warn("HALLAYM SHIELD fallback: local link checker only"));
  });
 }
}
module.exports={app};
