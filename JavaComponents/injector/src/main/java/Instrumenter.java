import static java.lang.System.exit;

public class Instrumenter {

    public static String apkPath = "";

    public static String componentName = "";

    public static String injectComponentType = "";

    public static String injectComponentPath = "";

    public static String outputFolder = "";

    public static String androidSdk = "";

    public static void main(String[] args) {
        if (args.length == 6) {
            apkPath = args[0];
            componentName = args[1];
            injectComponentType = args[2];
            injectComponentPath = args[3];
            outputFolder = args[4];
            androidSdk = args[5];
        }
        else {
            System.out.println("Wrong arguments, invocation should be like:\n" +
                    "java -jar injector.jar <apkPath> <componentName> <injectComponentType> <injectComponentPath> <outputFolder> <androidSdk>\n" +
                    "E.g., java -jar injector.jar /dev/shm/gnip/tmp/slice_inject/85D52FD7A0179D2951656B7D8D4FF2C30F574B04902BA7D070E02AD2FDDA1919.apk\n" +
                    "radioklub.sekhontech.com.service.MusicPlayerService\n" +
                    "service\n" +
                    "/dev/shm/gnip/tmp/slice_test/radioklub.sekhontech.com.service.MusicPlayerService\n" +
                    "/dev/shm/gnip/tmp/slice_inject/out_app\n" +
                    "/home/heping/android-sdk-linux/");
            exit(0);
        }

        SootUtility config = new SootUtility();
        config.initSoot(apkPath, injectComponentPath, outputFolder);

        Injector injector = new Injector(apkPath);
        injector.inject(componentName, injectComponentType);
        System.out.println("Success: Inject Success!");
    }
}
