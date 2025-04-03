import os
import shutil
import logging
import tempfile
import numpy as np
import time
import traceback
from attacker.adz import execute_action, finalize_attack, get_basic_info
from settings import config
from androguard.misc import AnalyzeAPK
from defender.drebin import get_drebin_feature
from defender.apigraph import get_apigraph_feature
from defender.mamadroid import get_mamadroid_feature
from defender.fd_vae import get_fd_vae_feature
from attacker.pst import PerturbationSelectionTree
from utils import green, sign_apk
from utils import red, cyan
from datasets.apks import APK


def random_select_attacker(apk, model, query_budget, output_result_dir):
    logging.info(
        cyan(f"Attack Start ----- APK: {apk.name}, Query budget: {query_budget}"))

    victim_feature = get_victim_feature(apk, model)
    if victim_feature is None:
        raise ValueError(
            f"Invalid feature extraction method: {model.feature}")

    source_label, source_confidence = get_model_predictions(
        model, victim_feature)
    if source_label == 0 or not source_confidence:
        return

    basic_info = get_basic_info(apk.location)
    if not basic_info:
        handle_self_crash(apk, output_result_dir)
        return

    tmp_dir, copy_apk_path = prepare_temp_dir(apk)
    perturbation_selector = initialize_perturbation_selector(basic_info)

    success, modification_crash, start_time = False, False, time.time()
    for attempt_idx in range(query_budget):
        if perform_attack_iteration(apk, model, perturbation_selector, tmp_dir, copy_apk_path):
            success = True
            break

    finalize_attack(apk, output_result_dir, success, modification_crash,
                    tmp_dir, copy_apk_path, start_time, attempt_idx)


def perform_attack_iteration(apk, model, perturbation_selector, tmp_dir, copy_apk_path):
    action = perturbation_selector.get_action()
    res, backup_dir, process_dir = execute_action(
        action, tmp_dir, copy_apk_path,
        perturbation_selector.inject_activity_name,
        perturbation_selector.inject_receiver_name,
        perturbation_selector.inject_receiver_data
    )

    if not res or 'Success' not in res.split("\n")[-2]:
        return True  # Indicates modification crash

    update_apk(copy_apk_path, process_dir, apk.name)
    if config['sign']:
        sign_apk(copy_apk_path)

    victim_feature = get_updated_victim_feature(apk, copy_apk_path, model)
    if victim_feature is None:
        return

    next_label = model.clf.predict(victim_feature)
    if next_label == 0:
        return False  # Indicates success

    cleanup_dirs([backup_dir, process_dir])
    return None  # Indicates continuation


def get_victim_feature(apk, model):
    feature_mapping = {
        "drebin": apk.drebin_feature,
        "apigraph": apk.apigraph_feature,
        "mamadroid": np.expand_dims(apk.mamadroid_family_feature, axis=0),
        "fd_vae": apk.fd_vae_feature
    }
    feature = feature_mapping.get(model.feature)
    return model.vec.transform(feature) if model.feature in ["drebin", "apigraph"] else feature


def get_updated_victim_feature(apk, copy_apk_path, model):
    feature_extractors = {
        "drebin": lambda: model.vec.transform(get_drebin_feature(copy_apk_path)),
        "apigraph": lambda: model.vec.transform(get_apigraph_feature(copy_apk_path)),
        "mamadroid": lambda: np.expand_dims(get_mamadroid_feature(copy_apk_path), axis=0),
        "fd_vae": lambda: apk.fd_vae_feature
    }
    return feature_extractors.get(model.feature, lambda: None)()


def get_model_predictions(model, victim_feature):
    source_label = model.clf.predict(victim_feature)
    confidence_extractors = {
        "svm": lambda: model.clf.decision_function(victim_feature),
        "mlp": lambda: model.clf.predict_proba(victim_feature)[0][1],
        "rf": lambda: model.clf.predict_proba(victim_feature)[0][1],
        "3nn": lambda: model.clf.predict_proba(victim_feature)[0][1],
        "fd_vae": lambda: model.clf.predict_proba(victim_feature)[0][1]
    }
    source_confidence = confidence_extractors.get(
        model.classifier, lambda: None)()
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
    shutil.copy(os.path.join(process_dir, apk_name + ".apk"), copy_apk_path)


def cleanup_dirs(dirs):
    for directory in dirs:
        shutil.rmtree(directory)
