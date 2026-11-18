"use strict";
const {TelegramClient}=require("teleproto");
const {StringSession}=require("teleproto/sessions");
const {NewMessage}=require("teleproto/events");
const {inspect,decrypt,senderHash}=require("./analyzer");

function createTelegramEngine({db,apiId,apiHash,key,retentionDays,onRisk}){
 const accounts=db.collection("accounts");
 const events=db.collection("riskEvents");
 const active=new Map();
 const settings={apiId:Number(apiId),apiHash};
 const ttl=Math.max(1,Math.min(30,Number(retentionDays)||7))*86400000;
 async function analyseIncoming(account,event){
   const msg=event?.message;
   if(!msg||msg.out||!event.isPrivate)return;
   const risk=inspect(msg.message||"",msg);
   const record={
     accountId:account.telegramId,
     type:risk.file?"file":"message",risk:risk.level,score:risk.score,
     reasons:risk.reasons,domains:risk.domains,
     file:risk.file,senderKey:msg.senderId?senderHash(account.telegramId,String(msg.senderId),key):null,
     createdAt:new Date(),expireAt:new Date(Date.now()+ttl)
   };
   await events.insertOne(record);
   onRisk(account.telegramId,{id:String(record._id),risk:record.risk,score:record.score,
      reasons:record.reasons,domains:record.domains,file:record.file,type:record.type,createdAt:record.createdAt});
 }
 async function activate(account,existing=null){
  if(!account.monitoring)return;
  const old=active.get(account.telegramId);
  if(old){active.delete(account.telegramId);if(old.client!==existing)await old.client.disconnect().catch(()=>{});}
  const client=existing||new TelegramClient(new StringSession(decrypt(account.sessionEncrypted,key)),settings.apiId,settings.apiHash,{connectionRetries:5});
  try{
   if(!existing){
    await client.connect();
    if(!(await client.checkAuthorization())){
     await accounts.updateOne({telegramId:account.telegramId},{$set:{monitoring:false,authExpired:true}});
     await client.disconnect();return;
    }
   }
   const handler=ev=>{analyseIncoming(account,ev).catch(err=>console.error("Scan error:",err.message));};
   client.addEventHandler(handler,new NewMessage({incoming:true}));
   active.set(account.telegramId,{client,handler});
  }catch(e){await client.disconnect().catch(()=>{});throw e;}
 }
 async function pause(id){
  const a=active.get(id);active.delete(id);if(a)await a.client.disconnect().catch(()=>{});
 }
 async function reload(id){
  const acc=await accounts.findOne({telegramId:id});
  if(!acc||!acc.monitoring){await pause(id);return;}
  await activate(acc);
 }
 async function revoke(id){
  const live=active.get(id);const acc=await accounts.findOne({telegramId:id});
  active.delete(id);
  let client=live?.client;
  if(!client&&acc){
   client=new TelegramClient(new StringSession(decrypt(acc.sessionEncrypted,key)),settings.apiId,settings.apiHash,{connectionRetries:2});
   await client.connect();
  }
  if(client){try{await client.logOut();}catch{}await client.disconnect().catch(()=>{});}
 }
 async function restore(){
  for(const a of await accounts.find({monitoring:true}).toArray()){
   try{await activate(a);}catch(e){console.error("Session restore failed:",e.message);}
  }
 }
 async function stopAll(){for(const id of [...active.keys()])await pause(id);}
 return {accounts,events,active,activate,pause,reload,revoke,restore,stopAll};
}
module.exports={createTelegramEngine};
