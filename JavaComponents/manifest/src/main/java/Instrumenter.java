import soot.PackManager;

import java.util.Random;

import static java.lang.System.exit;

public class Instrumenter {
    public static String apkPath = "";

    public static String outputFolder = "";

    public static String androidSdk = "";

    public static String modificationType = "";

    public static String modificationValue = "";

    public static String inject_activity_name = "";

    public static String inject_receiver_name = "";

    public static String inject_receiver_data = "";

    public static void main(String[] args) {
        if (args.length == 8) {
            apkPath = args[0];
            outputFolder = args[1];
            androidSdk = args[2];
            modificationType = args[3];
            modificationValue = args[4];
            inject_activity_name = args[5];
            inject_receiver_name = args[6];
            inject_receiver_data = args[7];
        }
        else {
            System.out.println("Wrong arguments, invocation should be like:\n" +
                    "java -jar manifest.jar <apkPath> <outputFolder> <androidSdk> <modificationType> <modificationValue> <inject_activity_name> <inject_receiver_name> <inject_receiver_data>\n" +
                    "E.g., java -jar manifest.jar /home/heping/AdvMal/paapk/test_apks/app-release.apk\n" +
                    "/home/heping/AdvMal/paapk/test_apks/out\n" +
                    "/home/heping/android-sdk-linux/\n" +
                    "uses-features\n" +
                    "android.hardware.microphone\n" +
                    "com.test.a\n" +
                    "com.test.b\n" +
                    "abcd");
            exit(0);
        }

        SootUtility config = new SootUtility();
        config.initSoot(apkPath, outputFolder);
        ManifestModifier modifier = new ManifestModifier();

        try {
            modifier.addProperties(apkPath, modificationType, modificationValue, inject_activity_name, inject_receiver_name, inject_receiver_data);
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error: An error occurred during the Manifest instrumentation!");
            exit(0);
        }
        PackManager.v().writeOutput(); //writes the final apk
        System.out.println("Success: Inject Success!");
    }
}
