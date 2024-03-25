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

    protected static List<String> primitiveList = new ArrayList<String>();

    static {
        excludePackagesList.add("java.");
        excludePackagesList.add("javax.");
        excludePackagesList.add("android.");
        excludePackagesList.add("androidx.");
        excludePackagesList.add("kotlin.");
        excludePackagesList.add("kotlinx.");
        excludePackagesList.add("junit.");
        excludePackagesList.add("sun.");
        excludePackagesList.add("org.w3c.");
        excludePackagesList.add("org.xmlpull.");
        excludePackagesList.add("org.xml.");
        excludePackagesList.add("org.json.");
        excludePackagesList.add("org.apache.http.");
        excludePackagesList.add("com.google.android.");
        excludePackagesList.add("com.google.");
        excludePackagesList.add("com.android.");
        excludePackagesList.add("dalvik.");
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
        primitiveList.add("java.");
        primitiveList.add("javax.");
        primitiveList.add("android.");
        primitiveList.add("androidx.");
        primitiveList.add("kotlin.");
        primitiveList.add("kotlinx.");
        primitiveList.add("junit.");
        primitiveList.add("sun.");
        primitiveList.add("org.w3c.");
        primitiveList.add("org.xmlpull.");
        primitiveList.add("org.xml.");
        primitiveList.add("org.json.");
        primitiveList.add("org.apache.http.");
        primitiveList.add("com.google.android.");
        primitiveList.add("com.google.");
        primitiveList.add("com.android.");
        primitiveList.add("dalvik.");
        primitiveList.add("int");
        primitiveList.add("String");
        primitiveList.add("dalvik.");
        primitiveList.add("byte");
        primitiveList.add("boolean");
        primitiveList.add("short");
        primitiveList.add("long");
        primitiveList.add("char");
        primitiveList.add("void");
        primitiveList.add("double");
        primitiveList.add("float");
        primitiveList.add("null");
    }

    static {
        excludeMethodList.add("<clinit>");
        excludeMethodList.add("<init>");
    }

    public static boolean isExcludeClass(SootClass sootClass) {
        if (sootClass.isPhantom()) {
            return true;
        }

        String packageName = sootClass.getName();
        for (String exclude : primitiveList) {
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

        for (String exclude : primitiveList) {
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

    public void initSoot(String apkPath, String output) {

        // Reset the Soot settings (it's necessary if you are analyzing several APKs)
        G.reset();

        // Generic options
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);

        // Read (APK Dex-to-Jimple) Options
        Options.v().set_src_prec(Options.src_prec_apk);

        ArrayList<String> paths = new ArrayList<>();
        paths.add(apkPath);
        Options.v().set_process_dir(paths);

        Options.v().set_force_android_jar(jarsPath);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_exclude(excludePackagesList);
        Options.v().set_no_bodies_for_excluded(true);

        // Write (APK Generation) Options
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_output_dir(output);

        Options.v().set_keep_line_number(true);
        Options.v().set_android_api_version(APK_API);
        Options.v().set_wrong_staticness(Options.wrong_staticness_fix);

        Scene.v().loadNecessaryClasses();

        PackManager.v().runPacks();

    }

}
