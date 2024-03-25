import polyglot.ast.While;
import soot.*;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.pdg.HashMutablePDG;
import soot.toolkits.graph.pdg.PDGNode;
import soot.util.Chain;

import java.util.*;

public class ComponentSlicer {

    public ArrayList<String> extract_dependency_class(ArrayList<String> dependencies, String target_class) {
        ArrayList<String> res = new ArrayList<String>();

        if (!dependencies.contains(target_class)) {
            dependencies.add(target_class);
        }

        for (SootClass sc : Scene.v().getApplicationClasses()) {
            if (sc.getName().equals(target_class)) {
                Chain<SootClass> interfaces = sc.getInterfaces();
                Chain<SootField> fields = sc.getFields();
                List<SootMethod> methods = sc.getMethods();

                // check the super class
                if (sc.hasSuperclass()) {
                    SootClass superclass = sc.getSuperclass();
                    if (!SootUtility.isExcludeClass(superclass)) {
                        res.add(superclass.getName());
                    }
                }

                // check the fields
                for (SootField field : fields) {
                    if (!SootUtility.isExcludeClass(field.getType().toString()) && !field.getType().toString().contains("[]")) {
                        if (!dependencies.contains(field.getType().toString()) && !res.contains(field.getType().toString())) {
                            res.add(field.getType().toString());
                        }
                    }
                }

                // check the interfaces  --- should we check the interface parameter?
                for (SootClass interfaceclass : interfaces) {
                    if (!SootUtility.isExcludeClass(interfaceclass)) {
                        if (!dependencies.contains(interfaceclass.getType().toString()) && !res.contains(interfaceclass.getType().toString())) {
                            res.add(interfaceclass.getType().toString());
                        }
                    }

                }

                // check the methods
                for (SootMethod sm : methods) {
                    if (!sm.hasActiveBody()) {
                        continue;
                    }
                    Body b = sm.getActiveBody();
                    boolean able = true;
                    try {
                        ExceptionalUnitGraph CFG = new ExceptionalUnitGraph(b);
                        HashMutablePDG PDG = new HashMutablePDG(CFG);
                        for (PDGNode node : PDG) {
                            for (PDGNode a : node.getDependents()) {
                                Block block = (Block) a.getNode();
                                for (Unit unit : block) {
                                    for (ValueBox v : unit.getUseAndDefBoxes()) {
                                        String tmp_feat = v.getValue().getType().toString();
                                        if (!dependencies.contains(tmp_feat) && !SootUtility.isExcludeClass(tmp_feat) && !res.contains(tmp_feat) && !tmp_feat.contains("[")) {
                                            res.add(tmp_feat);
                                        }
                                        String tmp = v.getValue().toString();
                                        if (tmp.startsWith("class")) {
                                            String dep = tmp.split("\"")[1].split(";")[0].substring(1).replace("/", ".");
                                            if (!SootUtility.isExcludeClass(dep) && !dep.contains("[]") && dep != target_class) {
                                                if (!dep.equals(sc.getName())) {
                                                    if (!dependencies.contains(dep) && !res.contains(dep)) {
                                                        res.add(dep);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception e) {
                        able = false;
                    }

                    if (!able) {
                        for (Local local_tmp : b.getLocals()) {
                            if (!SootUtility.isExcludeClass(local_tmp.getType().toString()) && !local_tmp.getType().toString().contains("[]")) {
                                if (!local_tmp.getType().toString().equals(sc.getName())) {
                                    if (!dependencies.contains(local_tmp.getType().toString()) && !res.contains(local_tmp.getType().toString())) {
                                        res.add(local_tmp.getType().toString());
                                    }
                                }
                            }
                        }

                        for (ValueBox value : b.getUseAndDefBoxes()) {
                            String tmp_feat = value.getValue().getType().toString();
                            if (!dependencies.contains(tmp_feat) && !SootUtility.isExcludeClass(tmp_feat) && !res.contains(tmp_feat) && !tmp_feat.contains("[")) {
                                res.add(tmp_feat);
                            }
                            String tmp = value.getValue().toString();
                            if (tmp.startsWith("class")) {
                                String dep = tmp.split("\"")[1].split(";")[0].substring(1).replace("/", ".");
                                if (!SootUtility.isExcludeClass(dep) && !dep.contains("[]") && !dep.equals(target_class)) {
                                    if (!dep.equals(sc.getName())) {
                                        if (!dependencies.contains(dep) && !res.contains(dep)) {
                                            res.add(dep);
                                        }
                                    }
                                }
                            }
                        }

                    }
                }

            }
        }

        if (res.size() > 0) {
            dependencies.addAll(res);
            for (String i : res) {
                if (!target_class.equals(i)) {
                    ArrayList<String> tmp_dep = extract_dependency_class(dependencies, i);
                    if (tmp_dep.size() > 0) {
                        for (String s : tmp_dep) {
                            if (!dependencies.contains(s)) {
                                dependencies.add(s);
                            }
                        }
                    }
                }
            }
        }

        Set<String> foo = new HashSet<String>(dependencies);
        return new ArrayList<String>(foo);
    }

    public void write_output(ArrayList<String> dependencies) {
        for (Iterator<SootClass> it = Scene.v().getApplicationClasses().snapshotIterator(); it.hasNext(); ) {
            SootClass sc = it.next();
            if (!dependencies.contains(sc.getName()) || sc.getName().contains("[]")) {
                sc.setPhantomClass();
            }
            else {
                sc.setApplicationClass();
            }
        }
        PackManager.v().writeOutput();
    }

}
