package uz.hallaym.shieldmessenger;

import org.junit.Test;
import java.util.List;
import static org.junit.Assert.*;

public class ThreatRulesTest {
 @Test public void safeGreeting() {
  assertTrue(ThreatRules.message("Salom",null,null).score < 25);
 }
 @Test public void fakeFineApkFlagged() {
  assertTrue(ThreatRules.message("Jarima kelgan! zudlik bilan oching","Jarima_2026.apk",null).score >= 65);
 }
 @Test public void falseExecutableFilenameFlagged() {
  assertTrue(ThreatRules.message("Hujjat","notice.exe",null).score >= 65);
 }
 @Test public void dangerousPermissionsRaiseScore() {
  assertTrue(ThreatRules.apkFile(true,true,false,false,List.of(
   "android.permission.READ_SMS","android.permission.REQUEST_INSTALL_PACKAGES"),true).score>=65);
 }
 @Test public void corruptArchiveIsHighRisk() {
  assertTrue(ThreatRules.apkFile(false,false,false,false,List.of(),false).score>=65);
 }
}
