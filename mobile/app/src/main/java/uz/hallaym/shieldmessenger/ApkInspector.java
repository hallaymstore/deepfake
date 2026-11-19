package uz.hallaym.shieldmessenger;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Offline, read-only static inspection. Never runs or installs analyzed APKs. */
public final class ApkInspector {
 private ApkInspector(){}
 private static final long MAX_BYTES=100L*1024*1024;

 public static final class Report {
  public final String name,sha256,packageName;
  public final long size;
  public final int entries,dexFiles,nativeLibraries,assets;
  public final List<String> permissions;
  public final ThreatRules.Finding finding;
  Report(String name,String hash,String packageName,long size,int entries,int dex,int libs,int assets,
         List<String> permissions,ThreatRules.Finding finding){
   this.name=name;this.sha256=hash;this.packageName=packageName;this.size=size;
   this.entries=entries;this.dexFiles=dex;this.nativeLibraries=libs;this.assets=assets;
   this.permissions=Collections.unmodifiableList(new ArrayList<>(permissions));this.finding=finding;
  }
 }

 /** Use Android's document picker; only copies to private temporary storage. */
 public static Report scan(Context ctx,Uri uri) throws Exception {
  if(!"content".equals(uri.getScheme()))throw new IOException("Faylni tizim tanlovchisi orqali oching");
  String displayName="Tanlangan fayl";
  try(Cursor cursor=ctx.getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){
   if(cursor!=null&&cursor.moveToFirst()){
    int col=cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
    if(col>=0&&cursor.getString(col)!=null)displayName=cursor.getString(col);
   }
  }
  File temp=File.createTempFile("shield-inspect-",".apk",ctx.getCacheDir());
  try {
   try(InputStream input=ctx.getContentResolver().openInputStream(uri);
       FileOutputStream out=new FileOutputStream(temp)){
    if(input==null)throw new IOException("Faylni o'qib bo'lmadi");
    byte[] block=new byte[65536];long count=0;int n;
    while((n=input.read(block))!=-1){
     count+=n;if(count>MAX_BYTES)throw new IOException("Fayl 100 MB cheklovidan katta");
     out.write(block,0,n);
    }
   }
   return inspect(ctx,temp,displayName);
  }finally{if(!temp.delete())temp.deleteOnExit();}
 }

 /** TDLib's own on-device file, strictly confined to this app's Telegram file directory. */
 public static Report scanTelegramFile(Context ctx,String path,String name) throws Exception {
  if(path==null||path.isEmpty())throw new IOException("Yuklangan fayl topilmadi");
  File root=new File(ctx.getFilesDir(),"tgfiles").getCanonicalFile();
  File file=new File(path).getCanonicalFile();
  if(!file.getPath().startsWith(root.getPath()+File.separator))
   throw new SecurityException("Fayl faqat Telegram klientining shaxsiy papkasidan tekshiriladi");
  if(!file.isFile())throw new IOException("Yuklangan fayl topilmadi");
  return inspect(ctx,file,name==null?"Telegramdan olingan APK":name);
 }

 private static Report inspect(Context ctx,File apk,String name) throws Exception {
  if(apk.length()>MAX_BYTES)throw new IOException("Fayl 100 MB cheklovidan katta");
  MessageDigest digest=MessageDigest.getInstance("SHA-256");
  try(InputStream input=new java.io.FileInputStream(apk)){
   byte[] chunk=new byte[65536];int n;
   while((n=input.read(chunk))!=-1)digest.update(chunk,0,n);
  }
  StringBuilder hash=new StringBuilder();
  for(byte b:digest.digest())hash.append(String.format(Locale.US,"%02x",b&255));
  int count=0,dex=0,libs=0,assets=0;
  boolean valid=false,hasManifest=false,traversal=false,zipBomb=false;
  try(ZipFile zip=new ZipFile(apk)){
   valid=true;
   Enumeration<? extends ZipEntry> entries=zip.entries();
   long unpacked=0;
   while(entries.hasMoreElements()){
    ZipEntry item=entries.nextElement();count++;
    if(count>12000){zipBomb=true;break;}
    String entry=item.getName().replace('\\','/');
    if(entry.equals("AndroidManifest.xml"))hasManifest=true;
    if(entry.startsWith("/")||entry.startsWith("../")||entry.contains("/../"))traversal=true;
    if(entry.matches("classes[0-9]*\\.dex"))dex++;
    if(entry.startsWith("lib/")&&entry.endsWith(".so"))libs++;
    if(entry.startsWith("assets/"))assets++;
    long size=item.getSize(),compressed=item.getCompressedSize();
    if(size>0){
     unpacked+=size;
     if(size>1_000_000_000L||unpacked>2_000_000_000L)zipBomb=true;
     if(compressed>0&&size>compressed*200L&&size>16_000_000L)zipBomb=true;
    }
   }
  }catch(IOException invalidZip){valid=false;}
  int flags=PackageManager.GET_PERMISSIONS|PackageManager.GET_SERVICES;
  PackageManager pm=ctx.getPackageManager();
  PackageInfo pkg=Build.VERSION.SDK_INT>=33
   ?pm.getPackageArchiveInfo(apk.getAbsolutePath(),PackageManager.PackageInfoFlags.of(flags))
   :pm.getPackageArchiveInfo(apk.getAbsolutePath(),flags);
  List<String> perms=pkg==null||pkg.requestedPermissions==null
   ? Collections.emptyList():Arrays.asList(pkg.requestedPermissions);
  boolean accessibility=false;
  if(pkg!=null&&pkg.services!=null)
   for(ServiceInfo svc:pkg.services)
    if("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(svc.permission))accessibility=true;
  ThreatRules.Finding finding=ThreatRules.apkFile(valid,hasManifest,traversal,zipBomb,perms,accessibility);
  return new Report(name,hash.toString(),pkg==null?"Aniqlanmadi":pkg.packageName,apk.length(),
                    count,dex,libs,assets,perms,finding);
 }
}
