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
from utils import green, red, cyan
from utils import run_java_component
from pprint import pprint
from datasets.apks import APK


def get_basic_info(apk_path):
    results = dict()
    try:
        # Analyze the APK file to get basic information
        a, d, dx = AnalyzeAPK(apk_path)

        # Get the APK version
        min_api_version = a.get_min_sdk_version() or 1
        max_api_version = a.get_max_sdk_version() or 1000
        results["min_api_version"] = int(min_api_version)
        results["max_api_version"] = int(max_api_version)

        # Get the uses-features
        results["uses-features"] = set(a.get_features())

        # Get the permissions
        results["permissions"] = set(a.get_permissions())

        # Get the intent actions and categories
        intent_actions = set()
        for node in a.get_android_manifest_xml().findall(".//action"):
            intent_actions.update(node.attrib.values())
        for node in a.get_android_manifest_xml().findall(".//category"):
            intent_actions.update(node.attrib.values())
        results["intents"] = intent_actions
    except Exception as e:  # Catch all exceptions to log them and return None
        apk_basename = os.path.basename(apk_path)
        logging.error(f"Error occurred in APK: {apk_basename}, Error: {e}")
        traceback.print_exc()
        return None

    return results


def execute_action(action, tmp_dir, apk_path, inject_activity_name, inject_receiver_name, inject_receiver_data):
    # Prepare backup and processing directories within the temporary directory
    backup_dir = os.path.join(tmp_dir, "backup")
    process_dir = os.path.join(tmp_dir, "process")
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)

    # Remove the existing AndroidManifest.xml in the tmp directory if it exists
    android_manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
    if os.path.exists(android_manifest_path):
        os.remove(android_manifest_path)

    # Copy the APK to the backup directory for safekeeping
    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))

    # Determine the modification type based on the action
    if action[1].name == "AndroidManifest.xml":
        # Path to the Java tool for manifest modifications
        jar = config['manifest']
        # Identify the specific modification needed on the manifest
        if action[2].name == "uses-features":
            modificationType = "feature"
        elif action[2].name == "permission":
            modificationType = "permission"
        else:
            # Additional checks for intent-related modifications
            if action[3].name == "activity_intent":
                modificationType = "activity_intent"
            elif action[3].name == "broadcast_intent":
                modificationType = "broadcast_intent"
            else:
                modificationType = "intent_category"

        # Prepare arguments for manifest modification
        args = [
            apk_path, process_dir, config['android_sdk'], modificationType,
            ";".join(
                action[-1].name), inject_activity_name, inject_receiver_name,
            inject_receiver_data
        ]
    else:
        # Path to the Java tool for injecting components into the APK
        jar = config['injector']
        # Prepare arguments for component injection
        args = [
            apk_path, action[-1].name[0], action[2].name,
            os.path.join(
                config['slice_database'], action[2].name +
                "s", action[-1].name[0],
                random.choice(action[-1].name[1])
            ),
            process_dir, config['android_sdk']
        ]

    # Execute the Java component to apply the modification
    res = run_java_component(jar, args, tmp_dir)
    return res, backup_dir, process_dir


def AdvDroidZero_attacker(apk, model, query_budget, output_result_dir):
    logging.info(cyan(
        "Attack Start ----- APK: {}, Query budget: {}".format(apk.name, query_budget)))
    victim_feature = None

    if model.feature == "drebin":
        victim_feature = model.vec.transform(apk.drebin_feature)
    elif model.feature == "mamadroid":
        victim_feature = np.expand_dims(apk.mamadroid_family_feature, axis=0)

    assert victim_feature is not None
    source_label = model.clf.predict(victim_feature)
    source_confidence = None
    if model.classifier == "svm":
        source_confidence = model.clf.decision_function(victim_feature)
    elif model.classifier == "mlp":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
    elif model.classifier == "rf":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
    elif model.classifier == "3nn":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
    elif model.classifier == "fd_vae_mlp":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
        source_label = source_confidence
    assert source_confidence is not None
    if source_label == 0:
        return

    # get the basic features in the source apk
    basic_info = get_basic_info(apk.location)

    if basic_info is None:
        logging.info(red("Attack Self Crash ----- APK: {}".format(apk.name)))
        final_res_dir = os.path.join(output_result_dir, "self_crash", apk.name)
        os.makedirs(final_res_dir, exist_ok=True)
        return

    # copy the backup apk
    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    os.makedirs(tmp_dir, exist_ok=True)
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk.location))
    shutil.copy(apk.location, copy_apk_path)

    PerturbationSelector = PerturbationSelectionTree(basic_info)
    PerturbationSelector.build_tree()
    inject_activity_name = PerturbationSelector.inject_activity_name
    inject_receiver_name = PerturbationSelector.inject_receiver_name
    inject_receiver_data = PerturbationSelector.inject_receiver_data
    PerturbationSelector.print_tree()

    modification_crash = False
    success = False
    start_time = time.time()
    for attempt_idx in range(query_budget):
        action = PerturbationSelector.get_action()

        # execute the action
        res, backup_dir, process_dir = execute_action(action, tmp_dir, copy_apk_path, inject_activity_name,
                                                      inject_receiver_name, inject_receiver_data)
        if not res:
            modification_crash = True
            break
        res = res.split("\n")
        if len(res) >= 2:
            if 'Success' not in res[-2]:
                modification_crash = True
                break

        os.remove(copy_apk_path)
        shutil.copy(os.path.join(process_dir, apk.name), copy_apk_path)
        if config['sign']:
            sign_apk(copy_apk_path)

        # re-extract the feature of the new apk
        victim_feature = None
        if model.feature == "drebin":
            victim_feature = get_drebin_feature(copy_apk_path)
            victim_feature = model.vec.transform(victim_feature)
        elif model.feature == "mamadroid":
            victim_feature = np.expand_dims(
                get_mamadroid_feature(copy_apk_path), axis=0)
        assert victim_feature is not None

        # query the model
        next_confidence = None
        if model.classifier == "svm":
            next_confidence = model.clf.decision_function(victim_feature)
        elif model.classifier == "mlp":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        elif model.classifier == "rf":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        elif model.classifier == "3nn":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        elif model.classifier == "fd_vae_mlp":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        assert next_confidence is not None

        next_label = model.clf.predict(victim_feature)
        if next_label == 0:
            success = True
            break

        # perturbation_results : 1 represents positive effects, 0 represents no effects. -1 represents negative effects
        if next_confidence < source_confidence - 1e-4:
            perturbation_results = 1
            source_confidence = next_confidence
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)
        elif next_confidence > source_confidence + 1e-4:
            perturbation_results = -1
            # backtrace the apk
            shutil.copy(os.path.join(backup_dir, apk.name), copy_apk_path)
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)
        else:
            perturbation_results = 0
            source_confidence = next_confidence
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)

        # update the tree
        PerturbationSelector.update_tree(action, perturbation_results)

    end_time = time.time()
    if success:
        logging.info("Attack Success ----- APK: {}".format(apk.name))
        final_res_dir = os.path.join(output_result_dir, "success", apk.name)
    else:
        if modification_crash:
            logging.info(
                "Attack Modification Crash ----- APK: {}".format(apk.name))
            final_res_dir = os.path.join(
                output_result_dir, "modification_crash", apk.name)
        else:
            logging.info("Attack Fail ----- APK: {}".format(apk.name))
            final_res_dir = os.path.join(output_result_dir, "fail", apk.name)

    os.makedirs(final_res_dir, exist_ok=True)

    if success:
        with open(os.path.join(final_res_dir, "efficiency.txt"), "w") as f:
            f.write(str(attempt_idx + 1) + "\n")
            f.write(str(end_time - start_time))

        if os.path.exists(copy_apk_path):
            shutil.copy(apk.location, os.path.join(
                final_res_dir, apk.name + ".source"))
            shutil.copy(copy_apk_path, os.path.join(
                final_res_dir, apk.name + ".adv"))

    shutil.rmtree(tmp_dir)
