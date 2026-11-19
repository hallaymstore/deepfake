"use strict";
/** Browser-only ZIP central-directory inspection. No code execution or network requests. */
(function(root){
 const MAX_BYTES=55*1024*1024;
 const decoder=new TextDecoder("utf-8",{fatal:false});
 const warn=(list,message)=>{if(!list.includes(message))list.push(message);};
 function inspectDirectory(arrayBuffer){
  const dv=new DataView(arrayBuffer);
  const raw=new Uint8Array(arrayBuffer);
  const out={validZip:false,hasManifest:false,dexFiles:0,nativeLibraries:0,
    resources:0,totalEntries:0,suspicious:[],status:"local-static-zip-only",level:"unknown"};
  const issues=out.suspicious;
  if(raw.length<22||raw[0]!==0x50||raw[1]!==0x4b){
   warn(issues,"ZIP/APK imzosi topilmadi");return out;
  }
  const low=Math.max(0,raw.length-22-65535);
  let eocd=-1;
  for(let i=raw.length-22;i>=low;i--){
   if(dv.getUint32(i,true)===0x06054b50 && i+22+dv.getUint16(i+20,true)<=raw.length){eocd=i;break;}
  }
  if(eocd<0){warn(issues,"ZIP markaziy katalogi topilmadi");return out;}
  const disk=dv.getUint16(eocd+4,true),diskCd=dv.getUint16(eocd+6,true);
  const entries=dv.getUint16(eocd+10,true);
  const dirSize=dv.getUint32(eocd+12,true);
  const dirOffset=dv.getUint32(eocd+16,true);
  if(disk!==0||diskCd!==0){warn(issues,"Ko'p diskli ZIP qo'llab-quvvatlanmaydi");return out;}
  if(entries===65535||dirSize===0xffffffff||dirOffset===0xffffffff){
   warn(issues,"ZIP64 formatining to'liq tahlili mavjud emas");return out;
  }
  if(dirOffset+dirSize>eocd||dirOffset>raw.length){
   warn(issues,"Arxiv markaziy katalogi noto'g'ri");return out;
  }
  out.validZip=true;
  let at=dirOffset;
  let manifestCount=0,unpacked=0;
  for(let i=0;i<entries;i++){
   if(i>=12000){warn(issues,"Arxivda haddan tashqari ko'p element");break;}
   if(at+46>eocd||dv.getUint32(at,true)!==0x02014b50){
    warn(issues,"ZIP katalog yozuvlari buzilgan");out.validZip=false;break;
   }
   const flags=dv.getUint16(at+8,true),method=dv.getUint16(at+10,true);
   const compressed=dv.getUint32(at+20,true),uncompressed=dv.getUint32(at+24,true);
   const nameLen=dv.getUint16(at+28,true),extraLen=dv.getUint16(at+30,true);
   const commentLen=dv.getUint16(at+32,true);
   if(at+46+nameLen+extraLen+commentLen>eocd){warn(issues,"ZIP fayl nomlari noto'g'ri");out.validZip=false;break;}
   const name=decoder.decode(raw.subarray(at+46,at+46+nameLen)).replace(/\\/g,"/");
   out.totalEntries++;
   if(name==="AndroidManifest.xml"){out.hasManifest=true;manifestCount++;}
   if(/^classes\d*\.dex$/i.test(name))out.dexFiles++;
   if(/^lib\/.+\.so$/i.test(name))out.nativeLibraries++;
   if(name.startsWith("res/")||name.startsWith("assets/"))out.resources++;
   if(name.startsWith("/")||name.startsWith("../")||name.includes("/../"))
    warn(issues,"ZIP ichida shubhali yo'l nomi");
   if(flags&1)warn(issues,"Shifrlangan ZIP elementi topildi");
   if(method!==0&&method!==8)warn(issues,"G'ayrioddiy siqish algoritmi");
   unpacked+=uncompressed;
   if(uncompressed>750*1024*1024||unpacked>2*1024*1024*1024||
      (compressed>0&&uncompressed>compressed*200&&uncompressed>10*1024*1024))
    warn(issues,"ZIP bombaga o'xshash siqilish ko'rsatkichi");
   at+=46+nameLen+extraLen+commentLen;
  }
  if(manifestCount>1)warn(issues,"Bir nechta AndroidManifest.xml mavjud");
  if(!out.hasManifest)warn(issues,"AndroidManifest.xml topilmadi");
  if(!out.dexFiles)warn(issues,"DEX bytecode topilmadi");
  if(out.totalEntries!==entries)warn(issues,"Katalogdagi elementlar soni mos kelmadi");
  out.level=issues.length?"warning":"unknown";
  return out;
 }
 async function inspectApkLocal(file){
  if(!file||typeof file.arrayBuffer!=="function")throw Error("Fayl tanlanmagan");
  if(file.size>MAX_BYTES)throw Error("55 MB chegarasidan katta APK");
  if(!/\.apk$/i.test(file.name||""))throw Error("Faqat APK fayllari");
  const buffer=await file.arrayBuffer();
  let hash;
  try{
   const digest=await root.crypto.subtle.digest("SHA-256",buffer);
   hash=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
  }catch{throw Error("Brauzeringiz SHA-256 hisoblashni qo'llab-quvvatlamaydi");}
  const result=inspectDirectory(buffer);
  return {...result,name:file.name,sha256:hash,bytes:buffer.byteLength,
   scope:"client-only",note:"Fayl serverga uzatilmaydi. Bu ZIP statik tahlili, antivirus hukmi emas."};
 }
 root.HallaymApk={inspect:inspectApkLocal,inspectDirectory,MAX_BYTES};
})(window);
