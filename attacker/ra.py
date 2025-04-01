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
from utils import sign_apk
from utils import red, cyan
from utils import run_java_component
from datasets.apks import APK


def get_basic_info(apk_path):
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        return {
            "min_api_version": int(a.get_min_sdk_version() or 1),
            "max_api_version": int(a.get_max_sdk_version() or 1000),
            "uses-features": set(a.get_features()),
            "permissions": set(a.get_permissions()),
            "intents": {
                *{node.attrib.values()
                  for node in a.get_android_manifest_xml().findall(".//action")},
                *{node.attrib.values() for node in a.get_android_manifest_xml().findall(".//category")}
            }
        }
    except Exception as e:
        logging.error(f"Error analyzing APK {os.path.basename(apk_path)}: {e}")
        traceback.print_exc()
        return None


def execute_action(action, tmp_dir, apk_path, inject_activity_name, inject_receiver_name, inject_receiver_data):
    backup_dir, process_dir = [os.path.join(
        tmp_dir, d) for d in ("backup", "process")]
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)

    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))

    jar, args = None, []
    if action[1].name == "AndroidManifest.xml":
        jar = config['manifest']
        modification_type = {
            "uses-features": "feature",
            "permission": "permission",
            "activity_intent": "activity_intent",
            "broadcast_intent": "broadcast_intent"
        }.get(action[2].name, "intent_category")
        args = [
            apk_path, process_dir, config['android_sdk'], modification_type,
            ";".join(
                action[-1].name), inject_activity_name, inject_receiver_name, inject_receiver_data
        ]
    else:
        jar = config['injector']
        args = [
            apk_path, action[-1].name[0], action[2].name,
            os.path.join(config['slice_database'], f"{action[2].name}s", action[-1].name[0],
                         random.choice(action[-1].name[1])),
            process_dir, config['android_sdk']
        ]

    return run_java_component(jar, args, tmp_dir), backup_dir, process_dir


def random_select_attacker(apk, model, query_budget, output_result_dir):
    logging.info(
        cyan(f"Attack Start ----- APK: {apk.name}, Query budget: {query_budget}"))

    victim_feature = get_victim_feature(apk, model)
    if victim_feature is None:
        return

    source_label, source_confidence = get_model_predictions(
        model, victim_feature)
    if source_label == 0 or source_confidence is None:
        return

    basic_info = get_basic_info(apk.location)
    if not basic_info:
        handle_self_crash(apk, output_result_dir)
        return

    tmp_dir, copy_apk_path = prepare_temp_dir(apk)
    perturbation_selector = initialize_perturbation_selector(basic_info)

    success, modification_crash, start_time = False, False, time.time()
    for attempt_idx in range(query_budget):
        action = perturbation_selector.get_action()
        res, backup_dir, process_dir = execute_action(
            action, tmp_dir, copy_apk_path,
            perturbation_selector.inject_activity_name,
            perturbation_selector.inject_receiver_name,
            perturbation_selector.inject_receiver_data
        )

        if not res or 'Success' not in res.split("\n")[-2]:
            modification_crash = True
            break

        update_apk(copy_apk_path, process_dir, apk.name)
        if config['sign']:
            sign_apk(copy_apk_path)

        victim_feature = get_updated_victim_feature(copy_apk_path, model)
        if victim_feature is None:
            break

        next_label = model.clf.predict(victim_feature)
        if next_label == 0:
            success = True
            break

        cleanup_dirs([backup_dir, process_dir])

    finalize_attack(apk, output_result_dir, success, modification_crash,
                    tmp_dir, copy_apk_path, start_time, attempt_idx)


def get_victim_feature(apk, model):
    if model.feature == "drebin":
        return model.vec.transform(apk.drebin_feature)
    elif model.feature == "mamadroid":
        return np.expand_dims(apk.mamadroid_family_feature, axis=0)
    return None


def get_model_predictions(model, victim_feature):
    source_label = model.clf.predict(victim_feature)
    source_confidence = None
    if model.classifier == "svm":
        source_confidence = model.clf.decision_function(victim_feature)
    elif model.classifier in {"mlp", "rf", "3nn", "fd_vae"}:
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
    return source_label, source_confidence


def handle_self_crash(apk, output_result_dir):
    logging.info(red(f"Attack Self Crash ----- APK: {apk.name}"))
    crash_dir = os.path.join(output_result_dir, "self_crash", apk.name)
    os.makedirs(crash_dir, exist_ok=True)


def prepare_temp_dir(apk):
    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk.location))
    shutil.copy(apk.location, copy_apk_path)
    return tmp_dir, copy_apk_path


def initialize_perturbation_selector(basic_info):
    selector = PerturbationSelectionTree(basic_info)
    selector.build_tree()
    return selector


def update_apk(copy_apk_path, process_dir, apk_name):
    shutil.copy(os.path.join(process_dir, apk_name), copy_apk_path)


def get_updated_victim_feature(copy_apk_path, model):
    if model.feature == "drebin":
        return model.vec.transform(get_drebin_feature(copy_apk_path))
    elif model.feature == "mamadroid":
        return np.expand_dims(get_mamadroid_feature(copy_apk_path), axis=0)
    return None


def cleanup_dirs(dirs):
    for directory in dirs:
        shutil.rmtree(directory)


def finalize_attack(apk, output_result_dir, success, modification_crash, tmp_dir, copy_apk_path, start_time, attempt_idx):
    result_type = "success" if success else "modification_crash" if modification_crash else "fail"
    final_res_dir = os.path.join(output_result_dir, result_type, apk.name)
    os.makedirs(final_res_dir, exist_ok=True)

    if success:
        with open(os.path.join(final_res_dir, "efficiency.txt"), "w") as f:
            f.write(f"{attempt_idx + 1}\n{time.time() - start_time}")
        shutil.copy(apk.location, os.path.join(
            final_res_dir, f"{apk.name}.source"))
        shutil.copy(copy_apk_path, os.path.join(
            final_res_dir, f"{apk.name}.adv"))

    shutil.rmtree(tmp_dir)
