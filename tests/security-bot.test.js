"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const {reportUrl}=require("../src/security-bot");
const {inspectApkBuffer}=require("../src/apk-inspect");
test("security bot: high pressure SMS text warned",()=>{
 assert.match(reportUrl("Zudlik bilan SMS kodni yuboring"),/Shubhali|Yuqori xavf/);
});
test("security bot: safe text not certified secure",()=>{
 assert.match(reportUrl("Salom"),/xavfsizligini isbotlamaydi/);
});
test("APK scanner: non-ZIP flagged without execution",async()=>{
 const result=await inspectApkBuffer(Buffer.from("not a zip"),"sample.apk");
 assert.equal(result.validZip,false);
 assert.ok(result.suspicious.length>0);
});
