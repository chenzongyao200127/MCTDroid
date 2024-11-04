import os
import logging
from utils import blue, green, red
from settings import config
from collections import defaultdict
import numpy as np
import traceback
from androguard.misc import AnalyzeAPK
import networkx as nx

TARGETED_FAMILIES = ["java.", "android.", "com.", "org.", "javax."]

def is_target_family(fam_smali):
    fam = fam_smali.split(";")[0][1:].replace("/", ".")
    return any(fam.startswith(target) for target in TARGETED_FAMILIES)

def get_call_graph(dx):
    CG = nx.DiGraph()
    nodes = dx.find_methods('.*', '.*', '.*', '.*')
    
    for m in nodes:
        API = m.get_method()
        class_name = API.get_class_name()
        
        if not is_target_family(class_name) or not m.get_xref_to():
            continue
            
        method_name = API.get_name()
        descriptor = API.get_descriptor()
        api_call = f"{class_name}->{method_name}{descriptor}"
        CG.add_node(api_call)

        for _, callee, _ in m.get_xref_to():
            callee_class = callee.get_class_name()
            if not is_target_family(callee_class):
                continue
                
            callee_node = f"{callee_class}->{callee.get_name()}{callee.get_descriptor()}"
            CG.add_node(callee_node)
            if not CG.has_edge(API, callee):
                CG.add_edge(api_call, callee_node)

    return CG

def smail_to_abstract(func_sin, abstract_list):
    class_name = func_sin.split(";")[0][1:].replace("/", ".")
    
    for abstract in abstract_list:
        if class_name.startswith(abstract):
            return abstract

    items = class_name.split('.')
    short_name_count = sum(1 for item in items if len(item) < 3)
    
    return "obfuscated" if short_name_count > (len(items) / 2) else "self-defined"

def build_markov_feature_androidguard(CG, output_path=None):
    with open(config['family_list']) as f:
        families = [line.strip() for line in f]
    families.extend(["self-defined", "obfuscated"])
    
    markov_family_features = np.zeros((len(families), len(families)))
    
    if CG is not None:
        total_edges = len(CG.edges())
        for caller, callee in CG.edges():
            caller_family = smail_to_abstract(caller, families[:-2])
            callee_family = smail_to_abstract(callee, families[:-2])
            caller_idx = families.index(caller_family)
            callee_idx = families.index(callee_family)
            markov_family_features[caller_idx][callee_idx] += 1
            
        if total_edges:
            markov_family_features = markov_family_features.flatten() / total_edges
        else:
            markov_family_features = markov_family_features.flatten()
    else:
        markov_family_features = markov_family_features.flatten()
        
    if output_path is not None:
        np.savez(output_path, family_feature=markov_family_features)
        logging.critical(blue(f'Successfully save the markov feature in: {output_path}'))
        
    return markov_family_features

def get_mamadroid_feature(apk_path, output_path=None, graph_path=None):
    try:
        _, _, dx = AnalyzeAPK(apk_path)
        CG = get_call_graph(dx)
        
        if graph_path is not None:
            nx.write_gml(CG, graph_path)
            
        logging.critical(green(f"Successfully extract APK: {os.path.basename(apk_path)}"))
        
    except:
        logging.error(red(f"Error occurred in APK: {os.path.basename(apk_path)}"))
        traceback.print_exc()
        CG = None
        
    return build_markov_feature_androidguard(CG, output_path)
