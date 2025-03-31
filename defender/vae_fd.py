import os
import logging
from settings import config
import numpy as np
import traceback
from androguard.misc import AnalyzeAPK
import networkx as nx

targeted_families = ["java.", "android.", "com.", "org.", "javax."]


def is_target_family(fam_smali: str) -> bool:
    fam = fam_smali.split(";")[0][1:].replace("/", ".")
    return any(fam.startswith(target) for target in targeted_families)


def get_call_graph(dx) -> nx.DiGraph:
    CG = nx.DiGraph()
    nodes = dx.find_methods('.*', '.*', '.*', '.*')
    for m in nodes:
        API = m.get_method()
        class_name = API.get_class_name()
        method_name = API.get_name()
        descriptor = API.get_descriptor()
        api_call = f"{class_name}->{method_name}{descriptor}"
        if not is_target_family(class_name) or not m.get_xref_to():
            continue

        CG.add_node(api_call)

        for _, callee, _ in m.get_xref_to():
            if not is_target_family(callee.get_class_name()):
                continue
            _callee = f"{callee.get_class_name()}->{callee.get_name()}{callee.get_descriptor()}"
            CG.add_node(_callee)
            if not CG.has_edge(api_call, _callee):
                CG.add_edge(api_call, _callee)

    return CG


def smali_to_abstract(func_sin: str, abstract_list: list) -> str:
    class_name = func_sin.split(";")[0][1:].replace("/", ".")
    for abstract in abstract_list:
        if class_name.startswith(abstract):
            return abstract

    items = class_name.split('.')
    if sum(len(item) < 3 for item in items) > (len(items) / 2):
        return "obfuscated"
    return "self-defined"


def build_markov_feature_androidguard(CG: nx.DiGraph, output_path: str = None) -> np.ndarray:
    with open(config['family_list'], "r") as f:
        families = [line.strip() for line in f]
    families.extend(["self-defined", "obfuscated"])

    markov_family_features = np.zeros((len(families), len(families)))
    if CG is not None:
        total_edges = len(CG.edges())
        for caller, callee in CG.edges():
            caller_family = smali_to_abstract(caller, families[:-2])
            callee_family = smali_to_abstract(callee, families[:-2])
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
            f'Successfully saved the Markov feature in: {output_path}')
    return markov_family_features


def get_mamadroid_feature(apk_path: str, output_path: str = None, graph_path: str = None) -> np.ndarray:
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        CG = get_call_graph(dx)
        if graph_path is not None:
            nx.write_gml(CG, graph_path)

        logging.critical(
            f'Successfully extracted APK: {os.path.basename(apk_path)}')
    except Exception as e:
        logging.error(f'Error occurred in APK: {os.path.basename(apk_path)}')
        traceback.print_exc()
        CG = None

    return build_markov_feature_androidguard(CG, output_path)
