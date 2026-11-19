"use strict";
const crypto=require("node:crypto");
const {Telegraf}=require("telegraf");
const {analyse}=require("./analyzer");
const {inspectApkBuffer,riskText,MAX_APK_BYTES}=require("./apk-inspect");
const REASONS_LIMIT=5;
const BOT_DOWNLOAD_LIMIT=19*1024*1024; // Public Telegram getFile has a strict 20 MB cap
/** Inspect visible text, Telegram text_link entities and available inline button URLs. */
function extractScanText(message){
 if(!message)return "";
 const visible=String(message.text||message.caption||"");
 const extra=[];
 for(const entity of [...(message.entities||[]),...(message.caption_entities||[])]){
  if(typeof entity?.url==="string"&&/^https?:\/\//i.test(entity.url))extra.push(entity.url);
 }
 for(const row of message.reply_markup?.inline_keyboard||[]){
  for(const button of row){
   if(typeof button?.url==="string"&&/^https?:\/\//i.test(button.url))extra.push(button.url);
  }
 }
 return [visible,...new Set(extra.slice(0,30))].join("\n").slice(0,10000);
}

function reportUrl(text){
 const value=analyse(text);
 if(value.score===0 && !/(?:https?:\/\/|www\.)/i.test(text))return "ℹ️ Bu xabarda havola yoki aniq firibgarlik belgisi topilmadi. APK fayl yoki shubhali havolani yuboring; oddiy matn uchun xavfsizlik xulosasi berilmaydi.";
 const label=value.level==="high"?"🔴 Yuqori xavf belgisi":value.level==="warning"?"🟠 Shubhali belgilar":"⚪ Aniq xavf belgisi topilmadi";
 return label+"\nXavf bahosi: "+value.score+"/100\n"+
 (value.reasons.length?"Sabablar: "+value.reasons.slice(0,REASONS_LIMIT).join("; "):"Faqat cheklangan qoida asosida tekshirildi")+
 "\n\nℹ️ 'Past' natija havolaning xavfsizligini isbotlamaydi.";
}
const minute=new Map();
function isRateLimited(id){
 const t=Date.now();const obj=minute.get(id)||{at:t,count:0};
 if(t-obj.at>60000){obj.at=t;obj.count=0;}
 obj.count++;minute.set(id,obj);
 if(minute.size>10000){for(const [k,v] of minute)if(t-v.at>60000)minute.delete(k);}
 return obj.count>12;
}
async function telegramFileBuffer(bot,fileId,size){
 if(size>BOT_DOWNLOAD_LIMIT)throw Error("Bot API 20 MB cheklovi. Katta APKni maxsus veb skanerga yuklang.");
 const href=(await bot.telegram.getFileLink(fileId)).toString();
 if(!href.startsWith("https://api.telegram.org/"))throw Error("Telegram yuklash manzili noto'g'ri");
 const abort=new AbortController();
 const timeout=setTimeout(()=>abort.abort(),18000);
 let bytes=0;const chunks=[];
 try{
  const response=await fetch(href,{signal:abort.signal,redirect:"error"});
  if(!response.ok||!response.body)throw Error("Telegram faylini yuklab bo'lmadi");
  const reader=response.body.getReader();
  for(;;){
   const {done,value}=await reader.read();
   if(done)break;
   bytes+=value.length;
   if(bytes>BOT_DOWNLOAD_LIMIT){await reader.cancel();throw Error("Bot API fayl limiti oshdi");}
   chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks,bytes);
 }finally{clearTimeout(timeout);}
}
async function createSecurityBot({db=null,origin,engine=null,token}){
 if(!token)return null;
 const bot=new Telegraf(token,{handlerTimeout:35000});
 const botMe=await bot.telegram.getMe();
 const name=botMe.username;
 const accounts=db?.collection("accounts")||null;
 const links=db?.collection("botLinkRequests")||null;
 if(links){
  await links.createIndex({tokenHash:1},{unique:true});
  await links.createIndex({expiresAt:1},{expireAfterSeconds:0});
 }
 const onlyPrivate=ctx=>ctx.chat?.type==="private";
 async function start(ctx){
  if(!onlyPrivate(ctx))return ctx.reply("Ulanish uchun botning shaxsiy chatiga o'ting.");
  return ctx.reply(
   "🛡 HALLAYM SHIELD\n\nMenga yuborilgan APK yoki havolani shu yerda tekshiraman.\n"+
   "Akkaunt monitoringi ixtiyoriy: QR orqali alohida tasdiqlash kerak. "+
   "Hech qachon Telegram login kodi yoki 2FA parolingizni ushbu chatga yubormang.\n\n"+
   "Buyruqlar: /connect /status /pause /resume /unlink /scan",
   {disable_web_page_preview:true});
 }
 bot.start(start);
 bot.command("help",start);
 bot.command("connect",async ctx=>{
  if(!onlyPrivate(ctx))return ctx.reply("Faqat bot bilan shaxsiy chatda foydalaning.");
  if(!links||!engine)return ctx.reply("ℹ️ QR orqali 24/7 akkaunt monitoringi hozircha sozlanmoqda. Hozir APK yoki havolani menga yuboring — men tekshiraman. Telegram kodlarini botga yubormang.");
  const raw=crypto.randomBytes(24).toString("hex");
  const t=Date.now();
  await links.insertOne({tokenHash:crypto.createHash("sha256").update(raw).digest("hex"),
    telegramId:String(ctx.from.id),botChatId:String(ctx.chat.id),
    createdAt:new Date(t),expiresAt:new Date(t+10*60*1000)});
  const url=origin+"/?pair="+raw;
  await ctx.reply("🔐 Bu havolada o'zingizning Telegram akkauntingizni QR orqali tasdiqlang.\n"+
   "10 daqiqada muddati tugaydi. Bu bot sizdan kod yoki parol olmaydi.\n"+
   "Telefoningizdagi shu akkaunt boshqa Telegram qurilmasida ochiq bo'lishi kerak.",
    {reply_markup:{inline_keyboard:[[{text:"Telegram himoyasini ulash",url}]]}});
 });
 bot.command("status",async ctx=>{
  if(!onlyPrivate(ctx))return;
  if(!accounts||!engine)return ctx.reply("✅ Botning fayl/havola tekshiruvi faol. Akkaunt monitoringi server bazasi va Telegram API kalitlari sozlanmagani uchun hozircha faol emas.");
  const a=await accounts.findOne({telegramId:String(ctx.from.id),botChatId:String(ctx.chat.id)});
  if(!a)return ctx.reply("Avtomatik monitoring ulanmagan. /connect");
  return ctx.reply("🛡 Monitoring: "+(a.monitoring?"YOQILGAN":"TO'XTATILGAN")+
   "\nReal vaqt ulanishi: "+(engine.active.has(a.telegramId)?"FAOL":"FAOL EMAS")+
   "\nSessiyani uzish: /unlink");
 });
 for(const [command,enabled] of [["pause",false],["resume",true]]){
  bot.command(command,async ctx=>{
   if(!onlyPrivate(ctx))return;
   if(!accounts||!engine)return ctx.reply("Avtomatik monitoring hali sozlanmagan. Fayl yoki havolani botga yuborib tekshiring.");
   const id=String(ctx.from.id);
   const a=await accounts.findOne({telegramId:id,botChatId:String(ctx.chat.id)});
   if(!a)return ctx.reply("Avval /connect orqali shaxsiy monitoringni ulang.");
   await accounts.updateOne({telegramId:id},{$set:{monitoring:enabled}});
   if(enabled)await engine.reload(id);else await engine.pause(id);
   await ctx.reply(enabled?"✅ Monitoring yoqildi":"⏸ Monitoring to'xtatildi");
  });
 }
 bot.command("unlink",async ctx=>{
  if(!onlyPrivate(ctx))return;
  if(!accounts||!engine)return ctx.reply("Bu akkauntga Telegram monitoring sessiyasi ulanmagan.");
  const id=String(ctx.from.id);
  const a=await accounts.findOne({telegramId:id,botChatId:String(ctx.chat.id)});
  if(!a)return ctx.reply("Ulangan akkaunt topilmadi.");
  await engine.revoke(id);
  await Promise.all([
   accounts.deleteOne({telegramId:id}),
   db.collection("riskEvents").deleteMany({accountId:id}),
   db.collection("webSessions").deleteMany({accountId:id})
  ]);
  await ctx.reply("✅ Monitoring sessiyasi bekor qilindi va shu akkauntning risk tarixi o'chirildi.");
 });
 async function inspectMessage(ctx,target){
  if(!target)return ctx.reply("Tekshirish uchun xabarga reply qiling yoki menga fayl/havolani yuboring.");
  if(isRateLimited(String(ctx.from?.id||ctx.chat?.id)))return ctx.reply("Bir daqiqalik limitga yetdingiz.");
  const text=extractScanText(target);
  const document=target.document;
  let answer="";
  if(text)answer+=reportUrl(text);
  if(document){
   const fileName=String(document.file_name||"document").slice(0,180);
   const fileSize=document.file_size||0;
   const isApk=/\.apk$/i.test(fileName)||document.mime_type==="application/vnd.android.package-archive";
   answer+=(answer?"\n\n":"")+"📎 "+fileName+"\n";
   if(!isApk)answer+="Bu fayl APK emas. Mazmuni hozircha antivirus bilan tekshirilmaydi.";
   else{
    answer+="⚠️ APK — o'rnatishdan oldin tekshirilishi kerak.\n";
    if(fileSize>BOT_DOWNLOAD_LIMIT){
     answer+="\n📦 Fayl "+(fileSize/1024/1024).toFixed(1)+" MB. Telegram Bot API 20 MBdan kattasini yuklay olmaydi.\n"+
       "🔎 55 MBgacha bo'lgan APKni o'rnatmasdan tahlil qilish: "+origin+"/scan-upload.html\n"+
       "Faylni shu sahifada o'zingiz tanlaysiz; serverda saqlanmaydi.";
    }else{
     try{
      const bytes=await telegramFileBuffer(bot,document.file_id,fileSize);
      const result=await inspectApkBuffer(bytes,fileName);
      answer+=riskText(result);
     }catch(e){answer+="Fayl tahlili yakunlanmadi: "+String(e.message).slice(0,120);}
    }
   }
  }
  if(!answer)answer="Bu xabarda tekshiriladigan matn, havola yoki fayl topilmadi.";
  return ctx.reply(answer.slice(0,3900),{disable_web_page_preview:true,reply_parameters:{message_id:ctx.message?.message_id}});
 }
 bot.command("scan",async ctx=>inspectMessage(ctx,ctx.message.reply_to_message || {text:(ctx.message.text||"").replace(/^\/scan(?:@\w+)?\s*/,"")}));
 bot.on("message",async ctx=>{
  const message=ctx.message;
  if(!message||!ctx.from)return;
  if(onlyPrivate(ctx))return inspectMessage(ctx,message);
  const body=String(message.text||message.caption||"");
  if(message.reply_to_message && new RegExp("@"+name+"\\b","i").test(body)){
   return inspectMessage(ctx,message.reply_to_message);
  }
 });
 bot.catch((err)=>console.error("Security bot error:",err?.message||"unknown"));
 const secret=crypto.createHash("sha256").update(token).digest("hex");
 bot.telegram.setMyCommands([
  {command:"start",description:"Xavfsizlik botini boshlash"},
  {command:"scan",description:"Javob berilgan xabarni tekshirish"},
  {command:"connect",description:"Shaxsiy himoyani ulash"},
  {command:"status",description:"Monitoring holati"},
  {command:"pause",description:"Monitoringni to'xtatish"},
  {command:"resume",description:"Monitoringni yoqish"},
  {command:"unlink",description:"Akkauntni uzish"}
 ]).catch(err=>console.warn("Bot commands not set:",err?.message));
 await bot.telegram.setWebhook(origin+"/telegram/webhook",{
  secret_token:secret,
  allowed_updates:["message"]
 });
 console.log("HALLAYM SHIELD webhook bot connected @"+name);
 return {
  username:name,
  webhookSecret:secret,
  handleUpdate:(update)=>bot.handleUpdate(update),
  async notify(telegramId,event){
   if(!accounts)return;
   const acc=await accounts.findOne({telegramId});
   if(!acc?.botChatId||!acc?.monitoring||event.risk==="low")return;
   const msg=(event.risk==="high"?"🔴 Yuqori xavf":"🟠 Shubhali xabar")+
    "\nXabar turi: "+(event.file?"Fayl":"Matn/havola")+
    "\nBaholash: "+event.score+"/100\n"+
    (event.reasons.length?"Sabablar: "+event.reasons.slice(0,5).join("; "):"Qoida detektori")+
    "\nℹ️ Foydalanuvchiga xabar matni yuborilmadi; qoidaviy baholash xavfsizlik kafolati emas.";
   await bot.telegram.sendMessage(acc.botChatId,msg);
  },
  stop(){/* Webhook needs no polling process to stop */}
 };
}
module.exports={createSecurityBot,reportUrl,isRateLimited,extractScanText};
