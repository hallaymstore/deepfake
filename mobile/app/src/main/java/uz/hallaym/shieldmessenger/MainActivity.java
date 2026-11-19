package uz.hallaym.shieldmessenger;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.drinkless.tdlib.Client;
import org.drinkless.tdlib.TdApi;
import java.util.ArrayList;
import java.util.List;

public final class MainActivity extends Activity {
 private static final int BACK=0xff071419;
 private static final int CARD=0xff102d2e;
 private static final int MINT=0xff5ff3bf;
 private static final int GREY=0xffa5c2bd;
 private static final int RED=0xffff9696;
 private Client client;
 private int apiId;
 private String apiHash;
 private LinearLayout view;
 private boolean signedIn=false;
 private long currentChat=0;
 private final java.util.concurrent.ExecutorService worker=java.util.concurrent.Executors.newSingleThreadExecutor();

 private LinearLayout messageList;
 private String openedTitle="";

 @Override public void onCreate(Bundle bundle) {
  super.onCreate(bundle);
  getWindow().setStatusBarColor(BACK);
  getWindow().setNavigationBarColor(0xff050b10);
  apiId=BuildConfig.TELEGRAM_API_ID;
  apiHash=BuildConfig.TELEGRAM_API_HASH;
  welcome();
 }
 private void welcome(){
  screen("Himoyalangan Telegram");
  text("XABARLAR • XAVFSIZLIK • APK",11,MINT);
  text("Telegram bilan oddiy telefon raqamingiz orqali kiring. Telegram dasturchi kodlari foydalanuvchilardan so'ralmaydi.",16,Color.WHITE);
  info("Yangi xabarlarni ko'rish, shubhali fayllarni belgilash va Telegramdan kelgan APK tarkibini uni o'rnatmasdan tekshirish.");
  button("➜ Telegram akkauntimga kirish",this::startClient);
  button("📦 Telefondagı APKni tekshirish",this::chooseApk);
  info("HALLAYM SHIELD mustaqil klient. Telegram sessiyasi va xabarlaringiz ushbu qurilmada saqlanadi. APK tekshiruvi zararli dasturni 100% aniqlash kafolati emas.");
 }
 private void startClient(){
  if(apiId<=0 || apiHash==null || !apiHash.matches("[a-fA-F0-9]{32}")){
   new AlertDialog.Builder(this).setTitle("Telegram ulanishi sozlanmagan")
    .setMessage("Ushbu test APKga Telegram ishlab chiquvchisining API konfiguratsiyasi kiritilmagan. "+
      "Oddiy foydalanuvchidan API ID yoki HASH so'ralmaydi. "+
      "Ilova ishlab chiquvchisi bir marta ilovani Telegram API kalitlari bilan build qiladi.")
    .setPositiveButton("Tushunarli",null).show();
   return;
  }
  screen("Telegramga ulanish");
  info("Telefon raqamingizni tasdiqlang. Login kodlari Render serveriga uzatilmaydi.");
  try{
   System.loadLibrary("tdjni");
   client=Client.create(this::update,null,null);
  }catch(Throwable e){
   info("TDLib ishga tushmadi: "+e.getClass().getSimpleName());
  }
 }
 private void update(TdApi.Object event){
  if(event instanceof TdApi.UpdateAuthorizationState){
   authorize(((TdApi.UpdateAuthorizationState)event).authorizationState);
  }else if(event instanceof TdApi.UpdateNewMessage){
   TdApi.Message message=((TdApi.UpdateNewMessage)event).message;
   if(message.isOutgoing)return;
   String body="";String filename="";String mime="";
   if(message.content instanceof TdApi.MessageText){
    TdApi.MessageText content=(TdApi.MessageText)message.content;
    if(content.text!=null)body=content.text.text;
   }else if(message.content instanceof TdApi.MessageDocument){
    TdApi.Document doc=((TdApi.MessageDocument)message.content).document;
    if(doc!=null){filename=doc.fileName;mime=doc.mimeType;}
   }
   ThreatRules.Finding finding=ThreatRules.message(body,filename,mime);
   if(finding.score>=25){
    runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Shubhali Telegram xabari")
       .setMessage(String.join("\n",finding.reasons)+"\n\nFaylni o'rnatmang. Bu faqat dastlabki xavf belgisi.")
       .setPositiveButton("Tushunarli",null).show());
   }
   if(currentChat==message.chatId)runOnUiThread(this::loadHistory);
  }
 }
 private void authorize(TdApi.AuthorizationState state){
  if(state instanceof TdApi.AuthorizationStateWaitTdlibParameters){
   TdApi.SetTdlibParameters params=new TdApi.SetTdlibParameters();
   params.databaseDirectory=getFilesDir().getAbsolutePath()+"/tgdb";
   params.filesDirectory=getFilesDir().getAbsolutePath()+"/tgfiles";
   params.useFileDatabase=true;
   params.useChatInfoDatabase=true;
   params.useMessageDatabase=true;
   params.useSecretChats=false;
   params.apiId=apiId;
   params.apiHash=apiHash;
   params.systemLanguageCode="uz";
   params.deviceModel=android.os.Build.MODEL;
   params.systemVersion=android.os.Build.VERSION.RELEASE;
   params.applicationVersion="HALLAYM SHIELD 0.1.0";
   send(params);
  }else if(state instanceof TdApi.AuthorizationStateWaitPhoneNumber){
   runOnUiThread(()->entry("Telefon raqami","+998…",InputType.TYPE_CLASS_PHONE,s->{
    TdApi.SetAuthenticationPhoneNumber fn=new TdApi.SetAuthenticationPhoneNumber();
    fn.phoneNumber=s;
    send(fn);
   }));
  }else if(state instanceof TdApi.AuthorizationStateWaitCode){
   runOnUiThread(()->entry("Telegram tasdiqlash kodi","Kod",InputType.TYPE_CLASS_NUMBER,s->{
    TdApi.CheckAuthenticationCode fn=new TdApi.CheckAuthenticationCode();
    fn.code=s;
    send(fn);
   }));
  }else if(state instanceof TdApi.AuthorizationStateWaitPassword){
   runOnUiThread(()->entry("Telegram 2FA paroli","Parol",InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD,s->{
    TdApi.CheckAuthenticationPassword fn=new TdApi.CheckAuthenticationPassword();
    fn.password=s;
    send(fn);
   }));
  }else if(state instanceof TdApi.AuthorizationStateWaitEmailAddress){
   runOnUiThread(()->entry("Telegram elektron pochta","Email",InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,s->{
    TdApi.SetAuthenticationEmailAddress fn=new TdApi.SetAuthenticationEmailAddress();
    fn.emailAddress=s;send(fn);
   }));
  }else if(state instanceof TdApi.AuthorizationStateWaitEmailCode){
   runOnUiThread(()->entry("Telegram email kodi","Kod",InputType.TYPE_CLASS_TEXT,s->{
    TdApi.CheckAuthenticationEmailCode fn=new TdApi.CheckAuthenticationEmailCode();
    fn.code=new TdApi.EmailAddressAuthenticationCode(s);send(fn);
   }));
  }else if(state instanceof TdApi.AuthorizationStateWaitOtherDeviceConfirmation){
   runOnUiThread(()->{
    screen("Telegram orqali tasdiqlash");
    info("Telegram ilovasida kirishni tasdiqlang.");
    info(((TdApi.AuthorizationStateWaitOtherDeviceConfirmation)state).link);
   });
  }else if(state instanceof TdApi.AuthorizationStateWaitRegistration){
   runOnUiThread(()->entry("Yangi akkaunt: ism","Ism",InputType.TYPE_CLASS_TEXT,s->{
    TdApi.RegisterUser fn=new TdApi.RegisterUser();fn.firstName=s;fn.lastName="";
    send(fn);
   }));
  }else if(state instanceof TdApi.AuthorizationStateReady){
   signedIn=true;runOnUiThread(this::loadChats);
  }else if(state instanceof TdApi.AuthorizationStateClosed){
   signedIn=false;runOnUiThread(()->{screen("Telegram sessiyasi yopildi");info("Ilovani qayta ishga tushiring.");});
  }
 }
 private void send(TdApi.Function<?> function){
  if(client==null)return;
  client.send(function,result->{
   if(result instanceof TdApi.Error){
    TdApi.Error e=(TdApi.Error)result;
    runOnUiThread(()->new AlertDialog.Builder(this)
      .setTitle("Telegram API").setMessage(e.message).setPositiveButton("Yopish",null).show());
   }
  });
 }
 private interface Submit{void run(String s);}
 private void entry(String title,String hint,int inputType,Submit action){
  screen(title);info("Bu ma'lumot to'g'ridan-to'g'ri qurilmadagi TDLib orqali Telegramga uzatiladi.");
  EditText value=new EditText(this);value.setHint(hint);value.setSingleLine();
  value.setInputType(inputType);value.setTextColor(Color.WHITE);
  value.setHintTextColor(GREY);view.addView(value);
  button("Tasdiqlash",()->{
   String input=value.getText().toString().trim();if(input.isEmpty())return;
   value.setText("");action.run(input);
  });
 }
 private void screen(String title){
  ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.setBackgroundColor(BACK);
  view=new LinearLayout(this);view.setPadding(22,18,22,24);view.setOrientation(LinearLayout.VERTICAL);
  scroll.addView(view);setContentView(scroll);
  TextView brand=text("⬡ HALLAYM SHIELD",23,MINT);
  text(title,18,Color.WHITE);
 }
 private TextView text(String t,int size,int color){
  TextView label=new TextView(this);label.setText(t);label.setTextSize(size);label.setTextColor(color);
  label.setPadding(7,15,7,15);view.addView(label);return label;
 }
 private void info(String t){text(t,13,GREY);}
 private void button(String label,Runnable handler){
  Button b=new Button(this);b.setAllCaps(false);b.setText(label);
  b.setTextColor(MINT);b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(CARD));
  view.addView(b);b.setOnClickListener(v->handler.run());
 }
 private void loadChats(){
  if(!signedIn||client==null)return;
  currentChat=0;openedTitle="";
  screen("Xabarlar");
  info("Telegram akkauntingiz • barcha chatlar shu telefon orqali TDLib bilan ishlaydi");
  button("📦 Yuklangan APKni tekshirish",this::chooseApk);
  button("↻ Chatlar ro'yxatini yangilash",this::loadChats);
  TdApi.GetChats fn=new TdApi.GetChats();
  fn.chatList=new TdApi.ChatListMain();fn.limit=60;
  client.send(fn,result->{
   if(result instanceof TdApi.Chats){
    long[] ids=((TdApi.Chats)result).chatIds;
    if(ids.length==0){
     runOnUiThread(()->info("Hozircha chatlar topilmadi. Telegram sinxronlanishini tekshiring."));
    }
    for(long id:ids){
     client.send(new TdApi.GetChat(id),chatObj->{
      if(chatObj instanceof TdApi.Chat){
       TdApi.Chat chat=(TdApi.Chat)chatObj;
       runOnUiThread(()->{
        if(currentChat!=0)return;
        button("💬 "+chat.title,()->openChat(chat.id,chat.title));
       });
      }
     });
    }
   }else if(result instanceof TdApi.Error){
    runOnUiThread(()->info("Chatlarni yuklash xatosi: "+((TdApi.Error)result).message));
   }
  });
 }
 private void openChat(long id,String title){
  currentChat=id;openedTitle=title;
  screen(title);
  button("← Xabarlarga qaytish",this::loadChats);
  button("↻ Xabarlarni yangilash",this::loadHistory);
  messageList=new LinearLayout(this);
  messageList.setOrientation(LinearLayout.VERTICAL);
  view.addView(messageList);
  EditText compose=new EditText(this);
  compose.setTextColor(Color.WHITE);
  compose.setHintTextColor(GREY);
  compose.setHint("Xabar yozing…");
  compose.setMinLines(1);compose.setMaxLines(3);
  view.addView(compose);
  button("➤ Xabarni yuborish",()->{
   String body=compose.getText().toString().trim();
   if(body.isEmpty())return;
   TdApi.FormattedText text=new TdApi.FormattedText();
   text.text=body;
   text.entities=new TdApi.TextEntity[0];
   TdApi.InputMessageText input=new TdApi.InputMessageText();
   input.text=text;
   TdApi.SendMessage sendMessage=new TdApi.SendMessage();
   sendMessage.chatId=id;sendMessage.inputMessageContent=input;
   send(sendMessage);
   compose.setText("");
   loadHistory();
  });
  loadHistory();
 }
 private void loadHistory(){
  if(currentChat==0||client==null||messageList==null)return;
  long id=currentChat;
  TdApi.GetChatHistory fn=new TdApi.GetChatHistory();
  fn.chatId=id;fn.limit=40;fn.offset=0;fn.fromMessageId=0;fn.onlyLocal=false;
  client.send(fn,result->{
   if(!(result instanceof TdApi.Messages))return;
   TdApi.Message[] msgs=((TdApi.Messages)result).messages;
   runOnUiThread(()->{
    if(id!=currentChat||messageList==null)return;
    messageList.removeAllViews();
    for(int i=msgs.length-1;i>=0;i--){
     TdApi.Message msg=msgs[i];
     String filename="";String mime="";
     TdApi.Document doc=null;
     String text="📨 Media";
     if(msg.content instanceof TdApi.MessageText) {
      TdApi.FormattedText formatted=((TdApi.MessageText)msg.content).text;
      text=formatted==null?"":formatted.text;
     } else if(msg.content instanceof TdApi.MessageDocument) {
      doc=((TdApi.MessageDocument)msg.content).document;
      if(doc!=null){filename=doc.fileName;mime=doc.mimeType;}
      text="📎 "+filename;
     }
     final TdApi.Document selectedDocument=doc;
     ThreatRules.Finding finding=ThreatRules.message(text,filename,mime);
     String textContent=(msg.isOutgoing?"Siz: ":"")+text;
     if(finding.score>=25)textContent+="\n⚠️ "+finding.severity+
       (finding.reasons.isEmpty()?"":"\n"+String.join(" · ",finding.reasons));
     if(selectedDocument!=null)textContent+="\n\n👆 Faylni bosib, o'rnatmasdan tekshiring";
     TextView row=new TextView(this);
     row.setText(textContent);row.setTextColor(finding.score>=65?RED:Color.WHITE);
     row.setTextSize(14);row.setPadding(14,15,14,15);
     row.setBackgroundColor(msg.isOutgoing?0xff143b34:0xff173039);
     LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);
     lp.setMargins(0,6,0,5);
     messageList.addView(row,lp);
     if(selectedDocument!=null)row.setOnClickListener(v->inspectTelegramDocument(selectedDocument));
    }
   });
  });
 }
 private void inspectTelegramDocument(TdApi.Document doc){
  if(doc==null||doc.document==null){info("Fayl mavjud emas");return;}
  String name=doc.fileName==null?"":doc.fileName;
  String mime=doc.mimeType==null?"":doc.mimeType;
  boolean apk=name.toLowerCase(java.util.Locale.ROOT).endsWith(".apk") ||
   "application/vnd.android.package-archive".equalsIgnoreCase(mime);
  if(!apk){
   new AlertDialog.Builder(this).setTitle("Fayl turi")
    .setMessage("Hozirgi versiya faqat APK faylining ichki tuzilishini tekshiradi. Bu fayl APK emas.")
    .setPositiveButton("Yopish",null).show();
   return;
  }
  new AlertDialog.Builder(this).setTitle("🛡️ "+name)
    .setMessage("APKni dastur sifatida O'RNATMASDAN, Telegram keshiga yuklab, "+
      "SHA-256, ZIP tuzilmasi, manifest ruxsatlari, DEX va native kutubxonalarni mahalliy tahlil qilamiz.\n\n"+
      "Fayl telefoningizdagi HALLAYM SHIELD shaxsiy xotirasida qoladi, serverga yuborilmaydi.")
    .setNegativeButton("Bekor qilish",null)
    .setPositiveButton("Yuklab tekshirish",(dialog,which)->downloadAndInspect(doc))
    .show();
 }
 private void downloadAndInspect(TdApi.Document doc){
  if(client==null||doc.document==null)return;
  final String name=doc.fileName==null?"Telegram.apk":doc.fileName;
  new AlertDialog.Builder(this).setTitle("Fayl tekshirilmoqda")
    .setMessage("Yuklab olish va tahlil boshlanmoqda. Fayl ishga tushirilmaydi.")
    .setPositiveButton("Tushunarli",null).show();
  TdApi.DownloadFile fn=new TdApi.DownloadFile();
  fn.fileId=doc.document.id;
  fn.priority=32;
  fn.offset=0;
  fn.limit=0;
  fn.synchronous=true;
  client.send(fn,result->{
   if(!(result instanceof TdApi.File)){
    runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Yuklash xatosi")
     .setMessage(result instanceof TdApi.Error?((TdApi.Error)result).message:
       "Faylni tekshirish uchun yuklab bo'lmadi.")
     .setPositiveButton("Yopish",null).show());
    return;
   }
   TdApi.File file=(TdApi.File)result;
   if(file.local==null || !file.local.isDownloadingCompleted || file.local.path==null){
    runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Fayl yuklanmadi")
     .setMessage("Yuklab olish yakunlanmadi. Qayta urinib ko'ring.")
     .setPositiveButton("Yopish",null).show());
    return;
   }
   final String path=file.local.path;
   worker.execute(()->{
    try {
     ApkInspector.Report report=ApkInspector.scanTelegramFile(this,path,name);
     runOnUiThread(()->showApkReport(report));
    }catch(Exception e){
     runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Tahlil xatosi")
      .setMessage(e.getMessage()).setPositiveButton("Yopish",null).show());
    }
   });
  });
 }
 private void showApkReport(ApkInspector.Report r){
  String reasons=r.finding.reasons.isEmpty()
     ?"Qoidaviy tekshiruv aniq xavf belgisini aniqlamadi. Bu xavfsizlik kafolati emas."
     :String.join("\n• ",r.finding.reasons);
  String summary="FAYL: "+r.name+"\nHolat: "+r.finding.severity+
   " ("+r.finding.score+"/100)\n\n"+
   "SHA-256: "+r.sha256+
   "\nPackage: "+r.packageName+
   "\nHajm: "+r.size+" bayt"+
   "\nArxiv elementlari: "+r.entries+
   "\nDEX modullari: "+r.dexFiles+
   "\nNative (.so) kutubxonalar: "+r.nativeLibraries+
   "\nAssets elementlari: "+r.assets+
   "\n\nBELGILAR\n• "+reasons+
   "\n\nSO'RALGAN RUXSATLAR\n"+(r.permissions.isEmpty()?"Aniqlanmadi":String.join("\n",r.permissions))+
   "\n\nXulosa avtomatik ekspertiza emas: o'rnatishdan oldin tekshiring. Hech narsa ishga tushirilmaydi yoki o'chirilmaydi.";
  new AlertDialog.Builder(this).setTitle("APK xavfsizlik hisoboti")
   .setMessage(summary).setPositiveButton("Yopish",null).show();
 }
 private void chooseApk(){
  Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT);
  pick.setType("*/*");pick.addCategory(Intent.CATEGORY_OPENABLE);
  startActivityForResult(pick,81);
 }
 @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){
  super.onActivityResult(requestCode,resultCode,data);
  if(requestCode!=81||resultCode!=RESULT_OK||data==null||data.getData()==null)return;
  Uri uri=data.getData();
  info("APKning tarkibi tekshirilmoqda...");
  worker.execute(()->{
   try{
    ApkInspector.Report r=ApkInspector.scan(this,uri);
    String summary=r.name+"\n\nRisk: "+r.finding.severity+" ("+r.finding.score+"/100)\n"+
      "SHA256: "+r.sha256+"\nPackage: "+r.packageName+
      "\nHajmi: "+r.size+" bayt\n\n"+String.join("\n",r.finding.reasons)+
      "\n\nRuxsatlar:\n"+String.join("\n",r.permissions)+
      "\n\nDiqqat: ruxsatlar zararli dasturni aniq isbotlamaydi. Ushbu ilova APKni o'rnatmaydi ham, avtomatik o'chirmaydi ham.";
    runOnUiThread(()->new AlertDialog.Builder(this).setTitle("APK tekshiruv hisoboti")
      .setMessage(summary).setPositiveButton("Yopish",null).show());
   }catch(Exception e){
    runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Tekshiruv xatosi")
      .setMessage(e.getMessage()).setPositiveButton("Yopish",null).show());
   }
  });
 }
 @Override protected void onDestroy(){
  worker.shutdown();
  super.onDestroy();
 }
}
