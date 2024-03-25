import soot.PackManager;
import soot.SootClass;

public class Injector {

    ManifestUtils manifestutil;

    public Injector(String apkPath) {
        manifestutil = new ManifestUtils(apkPath);
    }

    public void inject(String componentName, String injectComponentType) {
        // inject the component name and type in manifest
        manifestutil.inject(componentName, injectComponentType);

        PackManager.v().writeOutput(); //writes the final apk
    }

}
