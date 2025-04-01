# @article{aonzo2020obfuscapk,
#     title = "Obfuscapk: An open-source black-box obfuscation tool for Android apps",
#     journal = "SoftwareX",
#     volume = "11",
#     pages = "100403",
#     year = "2020",
#     issn = "2352-7110",
#     doi = "https://doi.org/10.1016/j.softx.2020.100403",
#     url = "https://www.sciencedirect.com/science/article/pii/S2352711019302791",
#     author = "Simone Aonzo and Gabriel Claudiu Georgiu and Luca Verderame and Alessio Merlo",
#     keywords = "Android, Obfuscation, Program analysis"
# }

from collections import defaultdict
import math
from abc import ABC, abstractmethod
import os
import shutil
import logging
import subprocess
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


def obfuscation_attack(apk, model, query_budget, output_result_dir):
    """Perform APK obfuscation attack using Obfuscapk."""
    logging.info(
        cyan(f"Attack started ----- APK: {apk.name}, Query Budget: {query_budget}"))

    # Verify Docker image installation
    try:
        subprocess.run(["docker", "run", "--rm", "-it", "obfuscapk", "--help"],
                       capture_output=True, text=True, check=True)
        logging.info("Obfuscapk Docker image test successful")
    except subprocess.CalledProcessError as e:
        logging.error(f"Obfuscapk Docker image test failed: {e.stderr}")
        return

    # Extract initial victim features
    victim_feature = extract_victim_feature(apk, model)
    if victim_feature is None:
        return

    # Get initial model predictions
    source_label, source_confidence = get_model_predictions(
        model, victim_feature)
    if source_label == 0 or source_confidence is None:  # Already benign or prediction failed
        return

    # Retrieve APK basic information
    basic_info = get_basic_info(apk.location)
    if not basic_info:
        handle_self_crash(apk, output_result_dir)
        return

    # Create temporary directory and copy APK
    tmp_dir = tempfile.mkdtemp()
    copy_apk_path = os.path.join(tmp_dir, apk.name)
    shutil.copy(apk.location, copy_apk_path)

    # Initialize attack state
    success, modification_crash, start_time = False, False, time.time()

    # Attempt obfuscation attack within query budget
    for attempt_idx in range(query_budget):
        # Define Obfuscapk obfuscation parameters
        # make sure the docker image is installed
        # ref: https://github.com/ClaudiuGeorgiu/Obfuscapk
        obfuscation_cmd = [
            "docker", "run", "--rm", "-it",
            "-u", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{tmp_dir}:/workdir",
            "obfuscapk",
            "-o", "RandomManifest",  # Randomize Manifest file
            "-o", "Rebuild",         # Rebuild APK
            "-o", "NewAlignment",    # Align APK
            "-o", "NewSignature",    # Resign APK
            copy_apk_path            # Input APK file path
        ]

        # Execute obfuscation
        try:
            result = subprocess.run(
                obfuscation_cmd, capture_output=True, text=True, check=True)
            logging.info(f"Obfuscation result: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Obfuscation failed: {e.stderr}")
            modification_crash = True
            break

        # Update APK path to obfuscated output
        obfuscated_apk_path = os.path.join(
            tmp_dir, f"{apk.name.split('.')[0]}_obfuscated.apk")
        if not os.path.exists(obfuscated_apk_path):
            logging.error(
                f"Obfuscated APK file not generated: {obfuscated_apk_path}")
            modification_crash = True
            break

        # Extract updated victim features
        victim_feature = extract_victim_feature(
            obfuscated_apk_path, model)
        if victim_feature is None:
            logging.error("Failed to extract features from obfuscated APK")
            modification_crash = True
            break

        # Predict label for obfuscated APK
        next_label = model.clf.predict(victim_feature)
        if next_label == 0:  # Successfully fooled the detector
            success = True
            break

    # Finalize attack and record results
    finalize_attack(apk, output_result_dir, success, modification_crash,
                    tmp_dir, obfuscated_apk_path if success else copy_apk_path,
                    start_time, attempt_idx)

# TODO: add more features and detectors


def extract_victim_feature(apk, model):
    if model.feature == "drebin":
        return model.vec.transform(apk.drebin_feature)
    elif model.feature == "mamadroid":
        return np.expand_dims(apk.mamadroid_family_feature, axis=0)
    return None

# TODO: add more features and detectors


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


def finalize_attack(apk, output_result_dir, success, modification_crash, tmp_dir, apk_path, start_time, attempt_idx):
    result_type = "success" if success else "modification_crash" if modification_crash else "fail"
    final_res_dir = os.path.join(output_result_dir, result_type, apk.name)
    os.makedirs(final_res_dir, exist_ok=True)

    if success:
        with open(os.path.join(final_res_dir, "efficiency.txt"), "w") as f:
            f.write(f"{attempt_idx + 1}\n{time.time() - start_time}")
        shutil.copy(apk.location, os.path.join(
            final_res_dir, f"{apk.name}.source"))
        shutil.copy(apk_path, os.path.join(final_res_dir, f"{apk.name}.adv"))

    shutil.rmtree(tmp_dir)
