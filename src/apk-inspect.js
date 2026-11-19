"use strict";
const crypto=require("node:crypto");
const yauzl=require("yauzl");
const MAX_APK_BYTES=18*1024*1024;
function inspectApkBuffer(data,name="telegram.apk"){
 if(!Buffer.isBuffer(data))return Promise.reject(Error("Binary buffer expected"));
 if(data.length>MAX_APK_BYTES)return Promise.reject(Error("APK hajmi 18 MB limitidan katta"));
 const sha256=crypto.createHash("sha256").update(data).digest("hex");
 return new Promise((resolve)=>{
  const report={name:String(name).slice(0,180),sha256,bytes:data.length,validZip:false,
   hasManifest:false,dexFiles:0,nativeLibraries:0,resources:0,totalEntries:0,
   suspicious:[],status:"static-zip-only"};
  const bad=(message)=>{if(!report.suspicious.includes(message))report.suspicious.push(message)};
  const finish=()=>resolve({...report,level:report.suspicious.length?"warning":"unknown",
   note:"Manifest ruxsatlari, kod xatti-harakati va virus signaturalari bu skanerda tekshirilmaydi."});
  if(data.subarray(0,2).toString("ascii")!=="PK"){
   bad("ZIP/APK imzosi mos emas");return finish();
  }
  yauzl.fromBuffer(data,{lazyEntries:true,autoClose:true,validateEntrySizes:true},(err,zip)=>{
   if(err||!zip){bad("APK arxivi ochilmadi");return finish();}
   report.validZip=true;
   let done=false;const close=()=>{if(done)return;done=true;finish();};
   zip.on("error",()=>{bad("Arxiv tuzilmasi noto'g'ri");close();});
   zip.on("end",()=>{
    if(!report.hasManifest)bad("AndroidManifest.xml topilmadi");
    if(!report.dexFiles)bad("DEX bytecode topilmadi");
    close();
   });
   zip.on("entry",entry=>{
    if(done)return;
    report.totalEntries++;
    if(report.totalEntries>10000){bad("Haddan ziyod arxiv elementlari");zip.close();return close();}
    const p=entry.fileName.replace(/\\/g,"/");
    if(p.startsWith("/")||p.startsWith("../")||p.includes("/../"))bad("ZIP path traversal belgisi");
    if(p==="AndroidManifest.xml")report.hasManifest=true;
    if(/^classes\d*\.dex$/.test(p))report.dexFiles++;
    if(/^lib\/.+\.so$/i.test(p))report.nativeLibraries++;
    if(p.startsWith("res/")||p.startsWith("assets/"))report.resources++;
    const len=entry.uncompressedSize||0;
    if(len>750*1024*1024||(entry.compressedSize>0&&len>entry.compressedSize*200&&len>10*1024*1024))
      bad("Arxiv siqilish darajasi g'ayrioddiy");
    zip.readEntry();
   });
   zip.readEntry();
  });
 });
}
function riskText(report){
 return (report.validZip?"APK ZIP tuzilmasi tekshirildi":"APK formati tekshirishdan o'tmadi")+
 "\nSHA-256: "+report.sha256+
 "\nHajm: "+(report.bytes/1024/1024).toFixed(2)+" MB"+
 "\nManifest: "+(report.hasManifest?"bor":"yo'q")+
 "\nDEX: "+report.dexFiles+" | Native lib: "+report.nativeLibraries+
 "\nArxiv elementlari: "+report.totalEntries+
 "\nBelgilar: "+(report.suspicious.length?report.suspicious.join("; "):"Shubhali ZIP tuzilma belgisi aniqlanmadi")+
 "\n⚠️ Bu antivirus xulosasi emas. APKni o'rnatmasdan qo'shimcha tekshiring.";
}
module.exports={inspectApkBuffer,riskText,MAX_APK_BYTES};
