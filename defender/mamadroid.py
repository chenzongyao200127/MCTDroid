import os
import shutil
import sys
import logging
from utils import blue, green, red
from settings import config
import subprocess
from collections import defaultdict
import numpy as np
import traceback
from androguard.misc import AnalyzeAPK
import networkx as nx

targeted_families = ["java.", "android.", "com.", "org.", "javax."]


def is_target_family(fam_smali):
    fam = fam_smali.split(";")[0][1:].replace("/", ".")
    for target in targeted_families:
        if fam.startswith(target):
            return True
    return False


def get_call_graph(dx):
    CG = nx.DiGraph()
    nodes = dx.find_methods('.*', '.*', '.*', '.*')
    for m in nodes:
        API = m.get_method()
        class_name = API.get_class_name()
        method_name = API.get_name()
        descriptor = API.get_descriptor()
        api_call = class_name + '->' + method_name + descriptor
        if not is_target_family(class_name):
            continue

        if len(m.get_xref_to()) == 0:
            continue
        CG.add_node(api_call)

        for other_class, callee, offset in m.get_xref_to():
            if not is_target_family(callee.get_class_name()):
                continue
            _callee = callee.get_class_name() + '->' + callee.get_name() + \
                callee.get_descriptor()
            CG.add_node(_callee)
            if not CG.has_edge(API, callee):
                CG.add_edge(api_call, _callee)

    return CG


def smail_to_abstract(func_sin, abstract_list):
    class_name = func_sin.split(";")[0][1:].replace("/", ".")
    for abstract in abstract_list:
        if class_name.startswith(abstract):
            return abstract

    items = class_name.split('.')
    item_len = len(items)
    count_l = 0
    for item in items:
        if len(item) < 3:
            count_l += 1
    if count_l > (item_len / 2):
        return "obfuscated"
    else:
        return "self-defined"


def build_markov_feature_androidguard(CG, output_path=None):
    families = []
    with open(config['family_list'], "r") as f:
        for line in f:
            families.append(line.strip())
    families.append("self-defined")
    families.append("obfuscated")
    markov_family_features = np.zeros((len(families), len(families)))
    if CG is not None:
        total_edges = len(CG.edges())
        for edge in CG.edges():
            caller = edge[0]
            callee = edge[1]
            caller_family = smail_to_abstract(caller, families[:-2])
            callee_family = smail_to_abstract(callee, families[:-2])
            caller_family_index = families.index(caller_family)
            callee_family_index = families.index(callee_family)
            markov_family_features[caller_family_index][callee_family_index] += 1
        if total_edges != 0:
            markov_family_features = markov_family_features.flatten() / total_edges
        else:
            markov_family_features = markov_family_features.flatten()
    else:
        markov_family_features = markov_family_features.flatten()
    if output_path is not None:
        np.savez(output_path, family_feature=markov_family_features)
        logging.critical(
            blue('Successfully save the markov feature in: {}'.format(output_path)))
    return markov_family_features


def get_mamadroid_feature(apk_path, output_path=None, graph_path=None):
    CG = None
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        CG = get_call_graph(dx)
        if graph_path is not None:
            nx.write_gml(CG, graph_path)

        logging.critical(
            green("Successfully extract APK: {}".format(os.path.basename(apk_path))))
    except:
        logging.error(
            red("Error occurred in APK: {}".format(os.path.basename(apk_path))))
        traceback.print_exc()

    return build_markov_feature_androidguard(CG, output_path)
