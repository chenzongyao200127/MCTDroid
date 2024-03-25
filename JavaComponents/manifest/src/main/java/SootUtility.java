import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.options.Options;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class SootUtility {
    protected static int APK_API = 23;
    protected static String jarsPath = Instrumenter.androidSdk + "platforms/android-" + APK_API + "/android.jar";
    protected static List<String> excludePackagesList = new ArrayList<String>();
    protected static List<String> excludeLibrariesList = new ArrayList<String>();
    protected static List<String> excludeMethodList = new ArrayList<String>();

    static {
        excludePackagesList.add("java.");
        excludePackagesList.add("sun.");
        excludePackagesList.add("android.");
        excludePackagesList.add("androidx.");
        excludePackagesList.add("javax.");
        excludePackagesList.add("android.support.");
        excludePackagesList.add("junit.");
        excludePackagesList.add("org.w3c");
        excludePackagesList.add("org.xmlpull");
        excludePackagesList.add("org.xml.sax.");
        excludePackagesList.add("org.json");
        excludePackagesList.add("org.apache.http.");
        excludePackagesList.add("com.google.android");
        excludePackagesList.add("com.android.");
        excludePackagesList.add("int");
        excludePackagesList.add("String");
        excludePackagesList.add("dalvik.");
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
        excludeLibrariesList.add("android.support.");
        excludeLibrariesList.add("junit.");
        excludeLibrariesList.add("sun.");
        excludeLibrariesList.add("org.w3c");
        excludeLibrariesList.add("org.xmlpull");
        excludeLibrariesList.add("org.xml.sax.");
        excludeLibrariesList.add("org.json");
        excludeLibrariesList.add("org.apache.http.");
        excludeLibrariesList.add("com.google.android");
        excludeLibrariesList.add("com.android.");
    }

    static {
        excludeMethodList.add("<clinit>");
        excludeMethodList.add("<init>");
    }

    public void initSoot(String apkPath, String output) {
        // Reset the Soot settings (it's necessary if you are analyzing several APKs)
        G.reset();

        // Generic options
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);

        // Read (APK Dex-to-Jimple) Options
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_force_android_jar(jarsPath);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_exclude(excludePackagesList);

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
