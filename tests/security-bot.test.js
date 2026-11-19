"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const {reportUrl,extractScanText}=require("../src/security-bot");
const {inspectApkBuffer}=require("../src/apk-inspect");
test("security bot: high pressure SMS text warned",()=>{
 assert.match(reportUrl("Zudlik bilan SMS kodni yuboring"),/Shubhali|Yuqori xavf/);
});
test("security bot: safe text not certified secure",()=>{
 assert.match(reportUrl("Salom"),/xavfsizlik xulosasi berilmaydi/);
});
test("APK scanner: non-ZIP flagged without execution",async()=>{
 const result=await inspectApkBuffer(Buffer.from("not a zip"),"sample.apk");
 assert.equal(result.validZip,false);
 assert.ok(result.suspicious.length>0);
});

test("Security bot reads text_link and available button URLs",()=>{
 const raw=extractScanText({
  text:"Mukofotni oling",
  entities:[{type:"text_link",url:"https://fake-login.example.com"}],
  reply_markup:{inline_keyboard:[[{text:"Click",url:"https://example.xyz/account"}]]}
 });
 assert.match(raw,/fake-login/);
 assert.match(raw,/example\.xyz/);
});
