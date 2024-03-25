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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
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

public class ManifestModifier {
    String namespace = "http://schemas.android.com/apk/res/android";
    String tools = "http://schemas.android.com/tools";

    public void addProperties(String apkPath, String modificationType, String modificationValue, String inject_activity_name, String inject_receiver_name, String inject_receiver_data) throws XmlPullParserException, IOException {
        System.out.println("Modifying the AndroidManifest.xml...");
        ProcessManifest processManifest = new ProcessManifest(apkPath);

        // get the manifest xml
        AXmlHandler axmlh = processManifest.getAXml();
        // get the manifest node
        AXmlNode manifest_node = axmlh.getDocument().getRootNode();
        // get the application node
        List<AXmlNode> application_nodes = axmlh.getNodesWithTag("application");
        AXmlNode application_node = null;
        try {
            application_node = application_nodes.get(0);
        }
        catch (Exception e) {
            application_node = manifest_node;
        }

        for (String mValue : modificationValue.split(";")) {
            if (Objects.equals(modificationType, "feature")) {
                AXmlNode feature_node = new AXmlNode("uses-feature", null, manifest_node);
                feature_node.addAttribute(new AXmlAttribute<String>("name", mValue, namespace));
                //feature_node.addAttribute(new AXmlAttribute<String>("required", "false", namespace));
            }
            else if (Objects.equals(modificationType, "permission")) {
                AXmlNode permission_node = new AXmlNode("uses-permission", null, manifest_node);
                permission_node.addAttribute(new AXmlAttribute<String>("name", mValue, namespace));
//            permission_node.addAttribute(new AXmlAttribute<String>("ignore", "ProtectedPermissions", tools));
            }
            else if (Objects.equals(modificationType, "activity_intent") || Objects.equals(modificationType, "intent_category")) {
                AXmlNode activity_node = processManifest.getActivity(inject_activity_name);
                AXmlNode intent_filter_node = null;
                if (activity_node == null) {
                    activity_node = new AXmlNode("activity", null, application_node);
                    activity_node.addAttribute(new AXmlAttribute<String>("name", inject_activity_name, namespace));
                    activity_node.addAttribute(new AXmlAttribute<String>("exported", "true", namespace));
                    intent_filter_node = new AXmlNode("intent-filter", null, activity_node);
                    AXmlNode random_action_node = new AXmlNode("action", null, intent_filter_node);
                    random_action_node.addAttribute((new AXmlAttribute<String>("name", inject_receiver_data, namespace)));
                }
                else {
                    intent_filter_node = activity_node.getChildrenWithTag("intent-filter").get(0);
                }
                AXmlNode inject_node = null;
                if (modificationType.equals("activity_intent")) {
                    inject_node = new AXmlNode("action", null, intent_filter_node);
                }
                else {
                    inject_node = new AXmlNode("category", null, intent_filter_node);
                }
                inject_node.addAttribute((new AXmlAttribute<String>("name", mValue, namespace)));
            }
            else if (Objects.equals(modificationType, "broadcast_intent")) {
                AXmlNode receiver_node = processManifest.getReceiver(inject_receiver_name);
                boolean has_receive = true;
                if (receiver_node == null) {
                    has_receive = false;
                    receiver_node = new AXmlNode("receiver", null, application_node);
                    receiver_node.addAttribute(new AXmlAttribute<String>("name", inject_receiver_name, namespace));
                    receiver_node.addAttribute(new AXmlAttribute<String>("exported", "true", namespace));
                }
                AXmlNode intent_filter_node = new AXmlNode("intent-filter", null, receiver_node);
                AXmlNode action_node = new AXmlNode("action", null, intent_filter_node);
                action_node.addAttribute((new AXmlAttribute<String>("name", mValue, namespace)));
                if (!has_receive) {
                    AXmlNode data_node = new AXmlNode("data", null, intent_filter_node);
                    data_node.addAttribute(new AXmlAttribute<String>("scheme", "http", namespace));
                    data_node.addAttribute(new AXmlAttribute<String>("host", inject_receiver_data, namespace));
                }
            }
        }


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
            }
        }
    }
}
