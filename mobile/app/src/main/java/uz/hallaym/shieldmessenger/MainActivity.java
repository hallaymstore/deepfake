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

 @Override public void onCreate(Bundle bundle) {
  super.onCreate(bundle);
  screen("HALLAYM SHIELD Messenger");
  info("Telefonning o'zida Telegram TDLib orqali ishlaydigan boshlang'ich klient. Xabarlar Render serverga uzatilmaydi.");
  apiId=BuildConfig.TELEGRAM_API_ID;
  apiHash=BuildConfig.TELEGRAM_API_HASH;
  if(apiId==0 || apiHash.length()!=32){
   apiId=getPreferences(MODE_PRIVATE).getInt("dev_api_id",0);
   apiHash=getPreferences(MODE_PRIVATE).getString("dev_api_hash","");
  }
  if(apiId<=0 || apiHash.length()!=32){
   configureApi();
   return;
  }
  startClient();
 }
 private void configureApi(){
  screen("Telegram dasturchi sozlamasi");
  info("Bu test yig'ilmasi: my.telegram.org saytidan olingan API ID va API HASHni shu telefonning o'zida kiriting. Oddiy foydalanuvchiga mo'ljallangan versiyada bular build vaqtida kiritiladi.");
  EditText idText=new EditText(this);
  idText.setHint("API ID");idText.setInputType(InputType.TYPE_CLASS_NUMBER);
  idText.setTextColor(Color.WHITE);view.addView(idText);
  EditText hashText=new EditText(this);
  hashText.setHint("API HASH (32 belgi)");hashText.setSingleLine();
  hashText.setTextColor(Color.WHITE);view.addView(hashText);
  button("Telegram klientini boshlash",()->{
   try{
    int n=Integer.parseInt(idText.getText().toString().trim());
    String h=hashText.getText().toString().trim();
    if(n<=0||!h.matches("[0-9a-fA-F]{32}"))throw new IllegalArgumentException();
    apiId=n;apiHash=h;
    getPreferences(MODE_PRIVATE).edit().putInt("dev_api_id",n).putString("dev_api_hash",h).apply();
    hashText.setText("");startClient();
   }catch(Exception ex){info("API ID raqam, HASH esa 32 ta hexadecimal belgi bo'lishi kerak.");}
  });
  button("📦 Faqat APKni tekshirish",this::chooseApk);
 }
 private void startClient(){
  screen("Telegramga ulanish");
  info("Telegram TDLib sessiyasi faqat shu telefonda. Chat matnlari Render serveriga yuborilmaydi.");
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
   if(finding.score>=65){
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
  if(!signedIn)return;currentChat=0;
  screen("Telegram chatlari");
  info("Xavfli APKlarni o'rnatishdan oldin qo'lda tahlil qiling. Bu Telegramning rasmiy ilovasi emas.");
  button("📦 APKni tekshirish",this::chooseApk);
  button("↻ Chatlarni yangilash",this::loadChats);
  TdApi.GetChats fn=new TdApi.GetChats();
  fn.chatList=new TdApi.ChatListMain();fn.limit=40;
  client.send(fn,result->{
   if(result instanceof TdApi.Chats){
    TdApi.Chats chats=(TdApi.Chats)result;
    for(long id:chats.chatIds){
     client.send(new TdApi.GetChat(id),obj->{
      if(obj instanceof TdApi.Chat){
       TdApi.Chat chat=(TdApi.Chat)obj;
       runOnUiThread(()->{
        if(currentChat!=0)return;
        button("💬 "+chat.title,()->openChat(chat.id,chat.title));
       });
      }
     });
    }
   }else if(result instanceof TdApi.Error){
    runOnUiThread(()->info("Chatlar: "+((TdApi.Error)result).message));
   }
  });
 }
 private void openChat(long id,String title){
  currentChat=id;screen(title);
  button("← Chatlarga qaytish",this::loadChats);
  button("↻ Xabarlarni yangilash",this::loadHistory);
  button("📦 APKni tekshirish",this::chooseApk);
  loadHistory();
 }
 private void loadHistory(){
  if(currentChat==0||client==null)return;
  long id=currentChat;
  TdApi.GetChatHistory fn=new TdApi.GetChatHistory();
  fn.chatId=id;fn.limit=40;fn.offset=0;fn.fromMessageId=0;fn.onlyLocal=false;
  client.send(fn,result->{
   if(!(result instanceof TdApi.Messages))return;
   TdApi.Message[] messages=((TdApi.Messages)result).messages;
   runOnUiThread(()->{
    if(currentChat!=id)return;
    for(int i=messages.length-1;i>=0;i--){
     TdApi.Message m=messages[i];String content="[Media]";
     String filename="";String mime="";
     if(m.content instanceof TdApi.MessageText){
      content=((TdApi.MessageText)m.content).text.text;
     }else if(m.content instanceof TdApi.MessageDocument){
      TdApi.Document doc=((TdApi.MessageDocument)m.content).document;
      if(doc!=null){filename=doc.fileName;mime=doc.mimeType;}
      content="📎 "+filename;
     }
     ThreatRules.Finding f=ThreatRules.message(content,filename,mime);
     if(f.score>=65)text("⚠️ "+content+"\n"+String.join(" · ",f.reasons),14,RED);
     else text((m.isOutgoing?"Siz: ":"")+content,14,Color.WHITE);
    }
   });
  });
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
