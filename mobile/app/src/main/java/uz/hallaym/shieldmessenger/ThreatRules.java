package uz.hallaym.shieldmessenger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Explainable, local heuristic signals: not a malware verdict. */
public final class ThreatRules {
 private ThreatRules() {}
 public static final class Finding {
  public final int score;
  public final String severity;
  public final List<String> reasons;
  Finding(int score, List<String> reasons) {
   this.score = Math.max(0, Math.min(100, score));
   this.reasons = Collections.unmodifiableList(new ArrayList<>(reasons));
   this.severity = this.score >= 65 ? "YUQORI XAVF" : this.score >= 25 ? "SHUBHALI" : "ANIQ BELGI TOPILMADI";
  }
 }
 private static final Pattern APK = Pattern.compile("(?i)(^|[^a-z0-9])[^\\s/\\\\]{0,150}\\.apk(?:\\b|$)");
 private static final Pattern EXE = Pattern.compile("(?i)\\.(?:exe|msi|bat|cmd|scr|vbs|ps1|js|jar|lnk)(?:\\b|$)");
 private static final Pattern URL = Pattern.compile("(?i)(?:https?://|www\\.)\\S+");
 public static Finding message(String message, String name, String mime) {
  String text = (message == null ? "" : message).toLowerCase(Locale.ROOT);
  String fn = name == null ? "" : name;
  List<String> reasons = new ArrayList<>();
  int score = 0;
  if (APK.matcher(fn).find() || APK.matcher(text).find()) {
   score += 40; reasons.add("Telegram orqali APK o'rnatish fayli: bu zararli ekanini isbotlamaydi, lekin tekshirish kerak");
  } else if (EXE.matcher(fn).find()) {
   score += 65; reasons.add("Bajariluvchi/skript fayl kengaytmasi");
  }
  if (mime != null && mime.equalsIgnoreCase("application/vnd.android.package-archive") && !fn.toLowerCase(Locale.ROOT).endsWith(".apk")) {
   score += 35; reasons.add("APK MIME fayl kengaytmasiga mos kelmaydi");
  }
  if (URL.matcher(text).find()) {
   score += 12; reasons.add("Xabarda havola mavjud");
  }
  if (Pattern.compile("(?i)(jarima|sud qarori|soliq|yutuq|sovg.a|штраф|приз|bonus)").matcher(text).find()) {
   score += 14; reasons.add("Soxta hujjat yoki mukofotga o'xshash mavzu");
  }
  if (Pattern.compile("(?i)(darhol|zudlik|tezda|shoshil|срочно|urgent)").matcher(text).find()) {
   score += 12; reasons.add("Shoshiltirish belgisi");
  }
  if (Pattern.compile("(?i)(sms kod|parol|пароль|otp|2fa|cvv)").matcher(text).find()) {
   score += 22; reasons.add("Maxfiy tasdiqlash ma'lumoti so'ralishi");
  }
  return new Finding(score,reasons);
 }
 public static Finding apkFile(boolean zipValid, boolean manifestPresent, boolean pathTraversal,
  boolean zipBombSignal, List<String> requestedPermissions, boolean accessibilityService) {
  List<String> reasons=new ArrayList<>();
  int score=0;
  if (!zipValid) { score+=85; reasons.add("ZIP/APK formati buzilgan yoki noma'lum"); }
  if (!manifestPresent) { score+=65; reasons.add("AndroidManifest.xml topilmadi"); }
  if (pathTraversal) { score+=80; reasons.add("Arxivda xavfli yo'l nomlari topildi"); }
  if (zipBombSignal) { score+=85; reasons.add("Arxivni haddan tashqari kengaytirish belgisi"); }
  List<String> perms = requestedPermissions == null ? Collections.emptyList() : requestedPermissions;
  for (String perm:perms) {
   if (perm==null) continue;
   if (perm.endsWith(".READ_SMS") || perm.endsWith(".RECEIVE_SMS") || perm.endsWith(".SEND_SMS")) {
    score+=22; reasons.add("SMS xabarlariga kirish ruxsati");
   } else if (perm.endsWith(".SYSTEM_ALERT_WINDOW")) {
    score+=14; reasons.add("Ekran ustiga oyna chizish ruxsati");
   } else if (perm.endsWith(".REQUEST_INSTALL_PACKAGES")) {
    score+=22; reasons.add("Boshqa APKlarni o'rnatishga so'rov huquqi");
   } else if (perm.endsWith(".READ_CALL_LOG") || perm.endsWith(".READ_CONTACTS")) {
    score+=12; reasons.add("Kontaktlar yoki qo'ng'iroqlar tarixiga kirish");
   }
  }
  if(accessibilityService) {score+=35; reasons.add("Accessibility xizmatini so'raydigan komponent");}
  return new Finding(score,reasons);
 }
}
