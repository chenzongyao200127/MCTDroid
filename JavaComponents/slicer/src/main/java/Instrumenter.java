import soot.PackManager;

import java.util.ArrayList;

import static java.lang.System.exit;

public class Instrumenter {
    public static String componentClassName = "";

    public static String apkPath = "";

    public static String outputFolder = "";

    public static String androidSdk = "";

    public static void main(String[] args) {
        if (args.length == 4) {
            componentClassName = args[0];
            apkPath = args[1];
            outputFolder = args[2];
            androidSdk = args[3];
        }
        else {
            System.out.println("Wrong arguments, invocation should be like:\n" +
                    "java -jar slicer.jar <componentClassName> <apkPath> <outputFolder> <androidSdk>\n" +
                    "E.g., java -jar slicer.jar radioklub.sekhontech.com.service.MusicPlayerService\n" +
                    "/dev/shm/gnip/tmp/slice_test/BA9CF038ED3EED64B6978852C57BFA52886C4101E60A3CEC3567301A59C5E26A.apk\n" +
                    "/dev/shm/gnip/tmp/slice_test/radioklub.sekhontech.com.service.MusicPlayerService/\n" +
                    "/home/heping/android-sdk-linux/");
            exit(0);
        }

        SootUtility config = new SootUtility();
        config.initSoot(apkPath, outputFolder);

        System.out.println("Slicing the class" + componentClassName + " from " + apkPath);

        ComponentSlicer slicer = new ComponentSlicer();
        ArrayList<String> dependence_class = new ArrayList<>();

        dependence_class = slicer.extract_dependency_class(new ArrayList<String>(), componentClassName);
//        System.out.println("The sliced dependency class:" + dependence_class);
        slicer.write_output(dependence_class);

        System.out.println("Successfully Slice the components!");
    }
}
