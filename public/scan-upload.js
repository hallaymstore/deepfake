"use strict";
const $=id=>document.getElementById(id);
const fileInput=$("apk"),button=$("scan"),status=$("status"),result=$("result");
let file=null;
fileInput.addEventListener("change",()=>{
 file=fileInput.files?.[0]||null;result.hidden=true;
 if(!file){button.disabled=true;return;}
 if(!/\.apk$/i.test(file.name)){button.disabled=true;status.textContent="Faqat .apk faylini tanlang.";return;}
 if(file.size>55*1024*1024){button.disabled=true;status.textContent="Fayl 55 MB chegarasidan katta.";return;}
 button.disabled=false;$("selected").textContent=file.name;
 status.textContent="Tanlandi: "+(file.size/1024/1024).toFixed(2)+" MB";
});
button.addEventListener("click",async()=>{
 if(!file)return;
 button.disabled=true;$("progress").hidden=false;result.hidden=true;
 status.textContent="APK shu qurilmada tekshirilmoqda. Fayl serverga uzatilmaydi…";
 try{
  if(!window.HallaymApk)throw Error("Mahalliy analizator yuklanmadi");
  const data=await window.HallaymApk.inspect(file);
  $("verdict").textContent=data.validZip?(data.suspicious.length?"⚠️ Shubhali arxiv belgisi topildi":"✓ APK tuzilmasi tahlil qilindi"):"⚠️ APK arxivi noto'g'ri";
  $("explanation").textContent=data.validZip?"Bu ZIP/APK statik tahlili bo'lib, antivirus xulosasi emas.":"Fayl APK formatida bo'lmasligi yoki arxiv tuzilmasi buzilgan bo'lishi mumkin.";
  $("hash").textContent=data.sha256;$("size").textContent=(data.bytes/1024/1024).toFixed(2)+" MB";
  $("manifest").textContent=data.hasManifest?"Mavjud":"Topilmadi";
  $("dex").textContent=String(data.dexFiles);
  $("libraries").textContent=String(data.nativeLibraries);
  $("entries").textContent=String(data.totalEntries);
  const ul=$("signals");ul.replaceChildren();
  for(const item of (data.suspicious?.length?data.suspicious:["Aniq ZIP tuzilma xavf belgisi topilmadi — zararli emasligini anglatmaydi."])){
   const li=document.createElement("li");li.textContent=item;ul.append(li);
  }
  result.hidden=false;status.textContent="Mahalliy statik tahlil yakunlandi. Fayl serverga yuborilmadi.";
  result.scrollIntoView({behavior:"smooth",block:"start"});
 }catch(e){
  status.textContent="Xatolik: "+e.message;
 }finally{$("progress").hidden=true;button.disabled=false;}
});
