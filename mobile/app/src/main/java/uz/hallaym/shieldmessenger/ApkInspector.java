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

public final class ApkInspector {
 private ApkInspector() {}
 private static final long MAX_BYTES=100L*1024*1024;
 public static final class Report {
  public final String name, sha256, packageName;
  public final long size;
  public final List<String> permissions;
  public final ThreatRules.Finding finding;
  public Report(String name, String sha256, String packageName, long size, List<String> permissions, ThreatRules.Finding finding) {
   this.name=name;this.sha256=sha256;this.packageName=packageName;this.size=size;
   this.permissions=permissions;this.finding=finding;
  }
 }
 public static Report scan(Context ctx, Uri uri) throws Exception {
  if(!"content".equals(uri.getScheme())) throw new IOException("Faylni tizim tanlovchisi orqali oching");
  String displayName="Tanlangan APK";
  try(Cursor cur=ctx.getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){
   if(cur!=null && cur.moveToFirst()){
    int index=cur.getColumnIndex(OpenableColumns.DISPLAY_NAME);
    if(index>=0)displayName=cur.getString(index);
   }
  }
  File tmp=File.createTempFile("shield-", ".apk",ctx.getCacheDir());
  try{
   MessageDigest dig=MessageDigest.getInstance("SHA-256");
   long count=0;
   try(InputStream in=ctx.getContentResolver().openInputStream(uri);
       FileOutputStream out=new FileOutputStream(tmp)){
    if(in==null)throw new IOException("Faylga kirish imkonsiz");
    byte[] bytes=new byte[65536];int read;
    while((read=in.read(bytes))!=-1){
     count+=read;
     if(count>MAX_BYTES)throw new IOException("100 MBdan katta fayl: tekshirish cheklangan");
     dig.update(bytes,0,read);out.write(bytes,0,read);
    }
   }
   StringBuilder hash=new StringBuilder();
   for(byte b:dig.digest())hash.append(String.format(Locale.US,"%02x",b&255));
   boolean zipOk=false,manifest=false,traversal=false,large=false;
   try(ZipFile zip=new ZipFile(tmp)){
    zipOk=true;
    Enumeration<? extends ZipEntry> entries=zip.entries();
    int entryCount=0;long totalUnpacked=0;
    while(entries.hasMoreElements()){
     ZipEntry entry=entries.nextElement();entryCount++;
     if(entryCount>12000){large=true;break;}
     String n=entry.getName().replace('\\','/');
     if(n.equals("AndroidManifest.xml"))manifest=true;
     if(n.startsWith("/")||n.startsWith("../")||n.contains("/../"))traversal=true;
     long size=entry.getSize(),packed=entry.getCompressedSize();
     if(size>0){
      totalUnpacked+=size;
      if(size>1_000_000_000L||totalUnpacked>2_000_000_000L)large=true;
      if(packed>0 && size>packed*200L && size>16_000_000L)large=true;
     }
    }
   }catch(IOException malformed){zipOk=false;}
   int flags=PackageManager.GET_PERMISSIONS|PackageManager.GET_SERVICES;
   PackageManager pm=ctx.getPackageManager();PackageInfo pkg;
   if(Build.VERSION.SDK_INT>=33)
    pkg=pm.getPackageArchiveInfo(tmp.getAbsolutePath(),PackageManager.PackageInfoFlags.of(flags));
   else pkg=pm.getPackageArchiveInfo(tmp.getAbsolutePath(),flags);
   List<String> perms=pkg==null||pkg.requestedPermissions==null
     ? Collections.emptyList():Arrays.asList(pkg.requestedPermissions);
   boolean accessibility=false;
   if(pkg!=null&&pkg.services!=null){
    for(ServiceInfo s:pkg.services)
     if("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(s.permission))accessibility=true;
   }
   ThreatRules.Finding finding=ThreatRules.apkFile(zipOk,manifest,traversal,large,perms,accessibility);
   return new Report(displayName,hash.toString(),pkg==null?"Aniqlanmadi":pkg.packageName,
    count,new ArrayList<>(perms),finding);
  }finally{
   if(!tmp.delete())tmp.deleteOnExit();
  }
 }
}
