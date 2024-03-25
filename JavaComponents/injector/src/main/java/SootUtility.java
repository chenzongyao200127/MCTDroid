import soot.*;
import soot.options.Options;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class SootUtility {
    protected static int APK_API = 23;
    protected static String jarsPath = Instrumenter.androidSdk + "platforms/android-" + APK_API + "/android.jar";
    protected static List<String> excludePackagesList = new ArrayList<String>();
    protected static List<String> excludeLibrariesList = new ArrayList<String>();
    protected static List<String> excludeMethodList = new ArrayList<String>();

    protected static List<String> componentClassList = new ArrayList<String>();

    static {
        excludePackagesList.add("java.");
        excludePackagesList.add("sun.");
        excludePackagesList.add("android.");
        excludePackagesList.add("androidx.");
        excludePackagesList.add("javax.");
        excludePackagesList.add("kotlin.");
        excludePackagesList.add("kotlinx.");
        excludePackagesList.add("junit.");
        excludePackagesList.add("org.w3c.");
        excludePackagesList.add("org.xmlpull.");
        excludePackagesList.add("org.xml.");
        excludePackagesList.add("org.json.");
        excludePackagesList.add("org.apache.http.");
        excludePackagesList.add("com.google.android.");
        excludePackagesList.add("com.google.");
        excludePackagesList.add("com.android.");
        excludePackagesList.add("dalvik.");
        excludePackagesList.add("int");
        excludePackagesList.add("String");
        excludePackagesList.add("byte");
        excludePackagesList.add("boolean");
        excludePackagesList.add("short");
        excludePackagesList.add("long");
        excludePackagesList.add("char");
        excludePackagesList.add("void");
        excludePackagesList.add("double");
        excludePackagesList.add("float");
        excludePackagesList.add("null");
    }

    static {
        excludeLibrariesList.add("java.");
        excludeLibrariesList.add("android.");
        excludeLibrariesList.add("androidx.");
        excludeLibrariesList.add("javax.");
        excludeLibrariesList.add("dalvik.");
        excludePackagesList.add("kotlin.");
        excludePackagesList.add("kotlinx.");
        excludeLibrariesList.add("android.support.");
        excludeLibrariesList.add("junit.");
        excludeLibrariesList.add("sun.");
        excludeLibrariesList.add("org.w3c.");
        excludeLibrariesList.add("org.xmlpull.");
        excludeLibrariesList.add("org.xml.sax.");
        excludeLibrariesList.add("org.json.");
        excludeLibrariesList.add("org.apache.http.");
        excludeLibrariesList.add("com.google.android");
        excludeLibrariesList.add("com.android.");
    }

    static {
        excludeMethodList.add("<clinit>");
        excludeMethodList.add("<init>");
    }

    static {
        componentClassList.add("android.support.v7.app.AppCompatActivity");
        componentClassList.add("android.app.Activity");
        componentClassList.add("android.app.Application");
        componentClassList.add("android.app.Service");
        componentClassList.add("android.app.IntentService");
        componentClassList.add("android.content.BroadcastReceiver");
        componentClassList.add("android.content.ContentProvider");
        componentClassList.add("android.app.Fragment");
        componentClassList.add("android.support.v4.app.Fragment");
    }

    public static boolean isExcludeClass(SootClass sootClass) {
        if (sootClass.isPhantom()) {
            return true;
        }

        String packageName = sootClass.getName();
        for (String exclude : excludePackagesList) {
            if (packageName.startsWith(exclude)) {
                return true;
            }
        }

        return false;
    }

    public static boolean isExcludeClass(String sootClass) {
        if (Scene.v().getSootClass(sootClass).isPhantom()) {
            return true;
        }

        for (String exclude : excludePackagesList) {
            if (sootClass.startsWith(exclude)) {
                return true;
            }
        }

        return false;
    }

    public static boolean isExcludedMethod(SootMethod sootMethod) {
        if (!sootMethod.hasActiveBody()) {
            return true;
        }

        String methodName = sootMethod.getName();
        for (String exclude : excludeMethodList) {
            if (methodName.startsWith(exclude)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isComponentClass(String superClass) {
        for (String exclude : componentClassList) {
            if (superClass.equals(exclude)) {
                return true;
            }
        }
        return false;
    }

    public void initSoot(String apkPath, String jimplePath, String output) {

        // Reset the Soot settings (it's necessary if you are analyzing several APKs)
        G.reset();

        // Generic options
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);

        // Read (APK Dex-to-Jimple) Options
        Options.v().set_src_prec(Options.src_prec_apk);

        ArrayList<String> paths = new ArrayList<>();
        paths.add(apkPath);
        paths.add(jimplePath);
        Options.v().set_process_dir(paths);

        Options.v().set_force_android_jar(jarsPath);
        Options.v().set_process_multiple_dex(true);

        // Write (APK Generation) Options
        Options.v().set_output_format(Options.output_format_dex);
        Options.v().set_output_dir(output);

        Options.v().set_keep_line_number(true);
        Options.v().set_android_api_version(APK_API);
        Options.v().set_wrong_staticness(Options.wrong_staticness_fix);

        Scene.v().loadNecessaryClasses();

        PackManager.v().runPacks();

    }

}
