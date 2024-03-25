import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlHandler;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.axml.ApkHandler;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.android.manifest.binary.BinaryAndroidApplication;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static java.lang.System.exit;

public class ManifestUtils {
    String namespace = "http://schemas.android.com/apk/res/android";
    String tools = "http://schemas.android.com/tools";
    String apkPath = "";
    ProcessManifest processManifest;
    AXmlHandler axmlh;
    RandomStringGenerator generator = new RandomStringGenerator();

    public ManifestUtils(String apkPath) {
        System.out.println("Loading the AndroidManifest.xml...");
        this.apkPath = apkPath;
        try {
            // get the manifest xml
            processManifest = new ProcessManifest(apkPath);
            axmlh = processManifest.getAXml();
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error: An error occurred during in the Manifest Loading!");
            exit(0);
        }
    }

    public void inject(String componentName, String injectComponentType) {
        // get the application node
        List<AXmlNode> application_nodes = axmlh.getNodesWithTag("application");
        AXmlNode application_node = null;
        try {
            application_node = application_nodes.get(0);
        }
        catch (Exception e) {
            System.out.println("Error: No Application Node!");
            exit(0);
        }
        String subprocess_name = ":" + generator.generate(20);
        String action_name = "com.gnip." + generator.generate(15);
        String authority_name = "com.gnip." + generator.generate(8);
        if (injectComponentType.equals("service")) {
            // inject service
            AXmlNode service_node = new AXmlNode("service", null, application_node);
            service_node.addAttribute(new AXmlAttribute<String>("name", componentName, namespace));
            service_node.addAttribute(new AXmlAttribute<String>("exported", "true", namespace));
            service_node.addAttribute(new AXmlAttribute<String>("enabled", "true", namespace));
            service_node.addAttribute(new AXmlAttribute<String>("process", subprocess_name, namespace));
        }
        else if (injectComponentType.equals("receiver")) {
            // inject receiver
            AXmlNode activity_node = new AXmlNode("receiver", null, application_node);
            activity_node.addAttribute(new AXmlAttribute<String>("name", componentName, namespace));
            activity_node.addAttribute(new AXmlAttribute<String>("exported", "true", namespace));
            activity_node.addAttribute(new AXmlAttribute<String>("process", subprocess_name, namespace));
            AXmlNode intent_filter_node = new AXmlNode("intent-filter", null, activity_node);
            AXmlNode action_node = new AXmlNode("action", null, intent_filter_node);
            action_node.addAttribute((new AXmlAttribute<String>("name", action_name, namespace)));
        }
        else if (injectComponentType.equals("provider")) {
            AXmlNode provider_node = new AXmlNode("provider", null, application_node);
            provider_node.addAttribute(new AXmlAttribute<String>("name", componentName, namespace));
            provider_node.addAttribute(new AXmlAttribute<String>("exported", "true", namespace));
            provider_node.addAttribute(new AXmlAttribute<String>("enabled", "true", namespace));
            provider_node.addAttribute(new AXmlAttribute<String>("process", subprocess_name, namespace));
            provider_node.addAttribute(new AXmlAttribute<String>("authorities", authority_name, namespace));
        }
        else {
            System.out.println("Error: Unknown Injection Type!");
            exit(0);
        }

        save_changes();
    }

    public void save_changes() {
        // This modification will change the source apk, we need to save the source apk to bak and then modify
        try {
            byte[] axmlBA = processManifest.getAXml().toByteArray();
            FileOutputStream fileOuputStream = new FileOutputStream("./AndroidManifest.xml");
            fileOuputStream.write(axmlBA);
            fileOuputStream.close();
            List<File> fileList = new ArrayList<File>();
            File newManifest = new File("./AndroidManifest.xml");
            fileList.add(newManifest);
            ApkHandler apkH = new ApkHandler(apkPath);
            apkH.addFilesToApk(fileList);
        }
        catch (Exception e) {
            System.out.println("Try a different XML method ...");
            try {
                String ManifestInString = processManifest.getAXml().toString();
                String[] Pieces = ManifestInString.split("\n");
                DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
                Document document = documentBuilder.newDocument();
                Integer actual_lvl = -1;
                Element actual = null;
                Element root1 = null;
                Boolean intent_filter = false;
                Element root_intent = null;
                Integer intent_level = 0;
                Integer intent_level_nodes = 0;
                Element intent_filter_node = null;
                for (String piece : Pieces) {
                    if (piece.startsWith("\t")) {
                        int count_tab = (int) piece.chars().filter(ch -> ch == '\t').count();
                        String tmp_piece = piece.replace("\t", "").trim();
                        if (tmp_piece.startsWith("-")) {

                            String[] pieces = tmp_piece.split(":");
                            String name = pieces[0].replace("-", "").trim();
                            String value = pieces[1].trim();
                            Attr attr = document.createAttribute(name);
                            attr.setValue(value);
                            actual.setAttributeNode(attr);

                        }
                        else {
                            if (tmp_piece.startsWith("intent-filter")) {
                                if (intent_filter) {
                                    Element subelement = document.createElement(tmp_piece);
                                    root_intent.appendChild(subelement);
                                    intent_filter_node = subelement;
                                }
                                else {
                                    intent_level = count_tab;
                                    intent_level_nodes = intent_level + 1;
                                    intent_filter = true;
                                    root_intent = actual;
                                    Element subelement = document.createElement(tmp_piece);
                                    root_intent.appendChild(subelement);
                                    intent_filter_node = subelement;
                                }
                            }
                            else {
                                if (intent_filter) {
                                    if (count_tab == intent_level_nodes) {
                                        Element subelement = document.createElement(tmp_piece);
                                        intent_filter_node.appendChild(subelement);
                                        actual = subelement;
                                    }
                                    else if (count_tab < intent_level) {
                                        intent_filter = false;
                                        intent_level = 0;
                                        intent_level_nodes = 0;
                                        Element subelement = document.createElement(tmp_piece);
                                        root_intent.getParentNode().appendChild(subelement);
                                        actual = subelement;
                                    }
                                }
                                else {
                                    if (count_tab > actual_lvl) {
                                        Element subelement = document.createElement(tmp_piece);
                                        actual.appendChild(subelement);
                                        actual = subelement;
                                    }
                                    else {
                                        Element subelement = document.createElement(tmp_piece);
                                        Node parent = actual.getParentNode();
                                        parent.appendChild(subelement);
                                        actual = subelement;
                                    }
                                }
                            }
                        }
                        if (count_tab > actual_lvl) {
                            if (!intent_filter) {
                                actual_lvl++;
                            }
                        }
                    }
                    else {
                        String tmp_piece = piece.replace("\t", "").trim();
                        if (actual == null) {
                            actual = document.createElement(tmp_piece);
                            document.appendChild(actual);
                            root1 = actual;
                            actual_lvl++;
                        }
                        else if (tmp_piece.startsWith("-")) {
                            String[] pieces = tmp_piece.split(":");
                            String name = pieces[0].replace("-", "").trim();
                            String value = pieces[1].trim();
                            Attr attr = document.createAttribute(name);
                            attr.setValue(value);
                            actual.setAttributeNode(attr);

                        }
                        else {
                            Element subelement = document.createElement(tmp_piece);
                            actual.appendChild(subelement);
                            actual = subelement;
                        }
                    }
                }
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                DOMSource domSource = new DOMSource(document);
                StreamResult streamResult = new StreamResult(new File("./AndroidManifest.xml"));

                transformer.transform(domSource, streamResult);

                System.out.println("Done creating XML File");
            }
            catch (ParserConfigurationException | TransformerException pce) {
                pce.printStackTrace();
                System.out.println("Error: Can not write AndroidManifest.xml! ");
                exit(0);
            }
        }
    }
}
