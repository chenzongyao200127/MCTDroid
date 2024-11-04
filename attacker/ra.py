from collections import defaultdict
import math
from abc import ABC, abstractmethod
import os
import shutil
import logging
import tempfile
import numpy as np
import random
import time
import traceback
from settings import config
from androguard.misc import AnalyzeAPK
from defender.drebin import get_drebin_feature
from defender.mamadroid import get_mamadroid_feature
from attacker.pst import PerturbationSelectionTree
from utils import sign_apk, green, red, cyan, run_java_component
from pprint import pprint
from datasets.apks import APK


def get_basic_info(apk_path):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        return {
            "min_api_version": int(a.get_min_sdk_version() or 1),
            "max_api_version": int(a.get_max_sdk_version() or 1000),
            "uses-features": set(a.get_features()),
            "permissions": set(a.get_permissions()),
            "intents": {value for node in a.get_android_manifest_xml().findall(".//action | .//category") for value in node.attrib.values()}
        }
    except Exception as e:
        logging.error(f"Error occurred in APK: {os.path.basename(apk_path)}, Error: {e}")
        traceback.print_exc()
        return None


def execute_action(action, tmp_dir, apk_path, inject_activity_name, inject_receiver_name, inject_receiver_data):
    backup_dir = os.path.join(tmp_dir, "backup")
    process_dir = os.path.join(tmp_dir, "process")
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)

    android_manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
    if os.path.exists(android_manifest_path):
        os.remove(android_manifest_path)

    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))

    if action[1].name == "AndroidManifest.xml":
        jar = config['manifest']
        modificationType = action[2].name if action[2].name in ["uses-features", "permission"] else action[3].name
        args = [apk_path, process_dir, config['android_sdk'], modificationType, ";".join(action[-1].name), inject_activity_name, inject_receiver_name, inject_receiver_data]
    else:
        jar = config['injector']
        args = [apk_path, action[-1].name[0], action[2].name, os.path.join(config['slice_database'], f"{action[2].name}s", action[-1].name[0], random.choice(action[-1].name[1])), process_dir, config['android_sdk']]

    res = run_java_component(jar, args, tmp_dir)
    return res, backup_dir, process_dir


def Random_attacker(apk, model, query_budget, output_result_dir):
    logging.info(cyan(f"Attack Start ----- APK: {apk.name}, Query budget: {query_budget}"))

    victim_feature = model.vec.transform(apk.drebin_feature) if model.feature == "drebin" else np.expand_dims(apk.mamadroid_family_feature, axis=0)
    source_label = model.clf.predict(victim_feature)
    source_confidence = model.clf.decision_function(victim_feature) if model.classifier == "svm" else model.clf.predict_proba(victim_feature)[0][1]

    if source_label == 0:
        return

    basic_info = get_basic_info(apk.location)
    if basic_info is None:
        logging.info(red(f"Attack Self Crash ----- APK: {apk.name}"))
        os.makedirs(os.path.join(output_result_dir, "self_crash", apk.name), exist_ok=True)
        return

    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk.location))
    shutil.copy(apk.location, copy_apk_path)

    PerturbationSelector = PerturbationSelectionTree(basic_info)
    PerturbationSelector.build_tree()
    inject_activity_name, inject_receiver_name, inject_receiver_data = PerturbationSelector.inject_activity_name, PerturbationSelector.inject_receiver_name, PerturbationSelector.inject_receiver_data

    modification_crash = False
    success = False
    start_time = time.time()

    for attempt_idx in range(query_budget):
        action = PerturbationSelector.get_action()
        res, backup_dir, process_dir = execute_action(action, tmp_dir, copy_apk_path, inject_activity_name, inject_receiver_name, inject_receiver_data)

        if not res or 'Success' not in res.split("\n")[-2]:
            modification_crash = True
            break

        os.remove(copy_apk_path)
        shutil.copy(os.path.join(process_dir, apk.name), copy_apk_path)
        if config['sign']:
            sign_apk(copy_apk_path)

        victim_feature = model.vec.transform(get_drebin_feature(copy_apk_path)) if model.feature == "drebin" else np.expand_dims(get_mamadroid_feature(copy_apk_path), axis=0)
        next_confidence = model.clf.decision_function(victim_feature) if model.classifier == "svm" else model.clf.predict_proba(victim_feature)[0][1]
        next_label = model.clf.predict(victim_feature)

        if next_label == 0:
            success = True
            break

        shutil.rmtree(backup_dir)
        shutil.rmtree(process_dir)

    end_time = time.time()
    final_res_dir = os.path.join(output_result_dir, "success" if success else "modification_crash" if modification_crash else "fail", apk.name)
    os.makedirs(final_res_dir, exist_ok=True)

    if success:
        with open(os.path.join(final_res_dir, "efficiency.txt"), "w") as f:
            f.write(f"{attempt_idx + 1}\n{end_time - start_time}")
        shutil.copy(apk.location, os.path.join(final_res_dir, f"{apk.name}.source"))
        shutil.copy(copy_apk_path, os.path.join(final_res_dir, f"{apk.name}.adv"))

    shutil.rmtree(tmp_dir)
