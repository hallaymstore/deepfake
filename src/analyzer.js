"use strict";
const crypto=require("node:crypto");
const {domainToASCII}=require("node:url");
const extensions=new Set(["exe","msi","apk","scr","bat","cmd","vbs","js","jse","ps1","hta","lnk","com","jar","wsf","iso"]);
const badZones=new Set(["zip","mov","top","click","xyz","sbs"]);
const clamp=n=>Math.min(100,Math.max(0,n));
const level=s=>s>=60?"high":s>=25?"warning":"low";
function analyse(text){
 const value=String(text||"").slice(0,32000);
 let score=0;let reasons=[];let domains=[];
 const matches=value.match(/(?:https?:\/\/|www\.)[^\s<>"'\]\)]+/giu)||[];
 for(const m of matches.slice(0,30)){
  try{
   const url=new URL(m.startsWith("www.")?"https://"+m:m);
   const host=domainToASCII(url.hostname.toLowerCase());if(!host)continue;
   domains.push(host);
   if(url.protocol==="http:"){score+=12;reasons.push("Shifrlanmagan HTTP havola");}
   if(host.startsWith("xn--")||host.includes(".xn--")){score+=30;reasons.push("Punycode domen: o'xshatma bo'lishi mumkin");}
   if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)){score+=27;reasons.push("IP manzil orqali havola");}
   if(badZones.has(host.split(".").at(-1))){score+=15;reasons.push("Xavfli ishlatilishi mumkin bo'lgan domen zonasi");}
   if(host.split(".").length>4){score+=10;reasons.push("Ko'p qavatli subdomen");}
   if(url.username||url.password){score+=40;reasons.push("Havola ichida yashirin hisob ma'lumoti");}
   if(/(?:telegram|google|instagram|bank|paypal|uzum|payme|click)-(?:login|verify|secure)/i.test(host)){
     score+=32;reasons.push("Brend nomiga o'xshatilgan domen");
   }
  }catch{
   if(/xn--/i.test(m)){score+=30;reasons.push("Punycode yoki noto'g'ri tuzilgan o'xshatma domen");}
  }
 }
 const otp=/(?:sms\s*kod|tasdiqlash\s*kod|bir\s*martalik\s*kod|parol|password|2fa|otp|cvv|pin\s*kod|код\s*из\s*смс|пароль|код\s*подтверждения)/iu;
 const urgent=/(?:tezda|zudlik\s*bilan|shoshil|bloklanad|yopilad|darhol|срочно|немедленно|urgent|immediately|account\s*suspended)/iu;
 const money=/(?:karta|hisob\s*raqam|to['’]?lov|pul\s*o['’]?tkaz|банк|карта|перевод|wallet|transfer)/iu;
 if(otp.test(value)){score+=24;reasons.push("Maxfiy kod yoki parol belgisi");}
 if(urgent.test(value)){score+=17;reasons.push("Shoshiltirish yoki bosim belgisi");}
 if(money.test(value)&&otp.test(value)){score+=20;reasons.push("Moliyaviy ma'lumot va maxfiy kod birga");}
 if(/(?:yutuq|sovg['’]?a|giveaway|приз|выигрыш)/iu.test(value)&&matches.length){score+=15;reasons.push("Mukofot/sovg'a havolasi");}
 score=clamp(score);
 return {score,level:level(score),reasons:[...new Set(reasons)],domains:[...new Set(domains)].slice(0,10)};
}
function mediaInfo(msg){
 const media=msg&&msg.media;if(!media)return null;
 const doc=media.document||media.photo||null;
 const attrs=doc?.attributes||[];
 const name=attrs.find(x=>typeof x.fileName==="string")?.fileName||"";
 const ext=name.includes(".")?name.split(".").at(-1).toLowerCase():"unknown";
 const mime=typeof doc?.mimeType==="string"?doc.mimeType:"unknown";
 const size=Number(doc?.size||0);
 return {extension:ext,mime,size:Number.isFinite(size)?size:0};
}
function inspect(text,msg){
 const base=analyse(text);const file=mediaInfo(msg);
 if(file){
  if(extensions.has(file.extension)){base.score=Math.max(base.score,file.extension==="apk"?65:80);base.reasons.push("Bajariluvchi yoki skript fayl turi");}
  if(file.extension==="pdf" && file.mime!=="application/pdf"){base.score=Math.max(base.score,35);base.reasons.push("Fayl turi va MIME nomuvofiq");}
 }
 base.level=level(base.score);
 base.reasons=[...new Set(base.reasons)];
 return {...base,file:file?{...file,scanStatus:"not_scanned",detail:"Fayl mazmuni tekshirilmagan"}:null};
}
function encrypt(value,keyHex){
 const key=Buffer.from(keyHex,"hex");if(key.length!==32)throw Error("Encryption key must be 32 bytes");
 const iv=crypto.randomBytes(12);const cipher=crypto.createCipheriv("aes-256-gcm",key,iv);
 const data=Buffer.concat([cipher.update(String(value),"utf8"),cipher.final()]);
 return Buffer.concat([iv,cipher.getAuthTag(),data]).toString("base64");
}
function decrypt(value,keyHex){
 const b=Buffer.from(value,"base64");
 const dec=crypto.createDecipheriv("aes-256-gcm",Buffer.from(keyHex,"hex"),b.subarray(0,12));
 dec.setAuthTag(b.subarray(12,28));return Buffer.concat([dec.update(b.subarray(28)),dec.final()]).toString("utf8");
}
const hash=x=>crypto.createHash("sha256").update(String(x)).digest("hex");
const senderHash=(account,sender,key)=>crypto.createHmac("sha256",Buffer.from(key,"hex")).update(account+":"+sender).digest("hex").slice(0,16);
module.exports={analyse,inspect,encrypt,decrypt,hash,senderHash};
