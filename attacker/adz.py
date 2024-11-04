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
from pathlib import Path
from typing import Dict, Optional, Set, Tuple, Union

from settings import config
from androguard.misc import AnalyzeAPK
from defender.drebin import get_drebin_feature
from defender.mamadroid import get_mamadroid_feature
from attacker.pst import PerturbationSelectionTree
from utils import sign_apk, green, red, cyan, run_java_component
from datasets.apks import APK


def extract_apk_info(apk_path: str) -> Optional[Dict]:
    """
    Extract basic information from an APK file.
    Returns None if analysis fails.
    """
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        
        # Extract API versions
        min_api = int(a.get_min_sdk_version() or 1)
        max_api = int(a.get_max_sdk_version() or 1000)
        
        # Extract manifest components
        manifest = a.get_android_manifest_xml()
        intent_actions = set()
        for node_type in ['action', 'category']:
            for node in manifest.findall(f'.//{node_type}'):
                intent_actions.update(node.attrib.values())
                
        return {
            "min_api_version": min_api,
            "max_api_version": max_api,
            "uses-features": set(a.get_features()),
            "permissions": set(a.get_permissions()),
            "intents": intent_actions
        }
        
    except Exception as e:
        logging.error(f"Error analyzing APK {os.path.basename(apk_path)}: {e}")
        traceback.print_exc()
        return None


def setup_modification_dirs(tmp_dir: str, apk_path: str) -> Tuple[str, str]:
    """Setup backup and processing directories for APK modification"""
    backup_dir = os.path.join(tmp_dir, "backup") 
    process_dir = os.path.join(tmp_dir, "process")
    
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)
    
    # Clean existing manifest
    manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        os.remove(manifest_path)
        
    # Backup original APK
    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))
    
    return backup_dir, process_dir


def get_modification_type(action: tuple) -> str:
    """Determine modification type from action tuple"""
    if action[1].name != "AndroidManifest.xml":
        return "component"
        
    component = action[2].name
    if component == "uses-features":
        return "feature"
    elif component == "permission":
        return "permission"
    elif action[3].name == "activity_intent":
        return "activity_intent"
    elif action[3].name == "broadcast_intent":
        return "broadcast_intent"
    return "intent_category"


def prepare_modification_args(action: tuple, apk_path: str, process_dir: str,
                            inject_activity: str, inject_receiver: str, 
                            inject_data: str) -> Tuple[str, list]:
    """Prepare arguments for APK modification"""
    mod_type = get_modification_type(action)
    
    if mod_type == "component":
        return config['injector'], [
            apk_path,
            action[-1].name[0],
            action[2].name,
            os.path.join(
                config['slice_database'],
                f"{action[2].name}s",
                action[-1].name[0],
                random.choice(action[-1].name[1])
            ),
            process_dir,
            config['android_sdk']
        ]
    
    return config['manifest'], [
        apk_path,
        process_dir, 
        config['android_sdk'],
        mod_type,
        ";".join(action[-1].name),
        inject_activity,
        inject_receiver,
        inject_data
    ]


def get_model_prediction(model, feature) -> Tuple[int, float]:
    """Get model prediction and confidence score"""
    confidence = None
    if model.classifier == "svm":
        confidence = model.clf.decision_function(feature)
    else:
        confidence = model.clf.predict_proba(feature)[0][1]
        
    label = model.clf.predict(feature)
    if model.classifier == "fd_vae_mlp":
        label = confidence
        
    return label, confidence


def execute_attack(apk: APK, model, query_budget: int, output_dir: str) -> None:
    """Execute adversarial attack on APK"""
    logging.info(cyan(f"Starting attack on {apk.name} with budget {query_budget}"))

    # Get initial prediction
    if model.feature == "drebin":
        victim_feature = model.vec.transform(apk.drebin_feature)
    else:
        victim_feature = np.expand_dims(apk.mamadroid_family_feature, axis=0)
        
    source_label, source_confidence = get_model_prediction(model, victim_feature)
    if source_label == 0:
        return

    # Extract APK info
    basic_info = extract_apk_info(apk.location)
    if not basic_info:
        logging.info(red(f"Attack failed - self crash: {apk.name}"))
        Path(output_dir, "self_crash", apk.name).mkdir(parents=True, exist_ok=True)
        return

    # Setup working directory
    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    work_apk = Path(tmp_dir) / apk.name
    shutil.copy(apk.location, work_apk)

    # Initialize perturbation selector
    selector = PerturbationSelectionTree(basic_info)
    selector.build_tree()
    selector.print_tree()

    # Attack loop
    modification_crash = False
    success = False
    start_time = time.time()
    
    for attempt in range(query_budget):
        action = selector.get_action()
        
        # Execute modification
        backup_dir, process_dir = setup_modification_dirs(tmp_dir, str(work_apk))
        jar_path, args = prepare_modification_args(
            action, str(work_apk), process_dir,
            selector.inject_activity_name,
            selector.inject_receiver_name, 
            selector.inject_receiver_data
        )
        
        result = run_java_component(jar_path, args, tmp_dir)
        if not result or 'Success' not in result.split('\n')[-2]:
            modification_crash = True
            break
            
        # Update working APK
        os.remove(work_apk)
        shutil.copy(os.path.join(process_dir, apk.name), work_apk)
        if config['sign']:
            sign_apk(work_apk)

        # Get new prediction
        if model.feature == "drebin":
            new_feature = model.vec.transform(get_drebin_feature(work_apk))
        else:
            new_feature = np.expand_dims(get_mamadroid_feature(work_apk), axis=0)
            
        new_label, new_confidence = get_model_prediction(model, new_feature)
        
        if new_label == 0:
            success = True
            break

        # Update selector based on result
        if new_confidence < source_confidence - 1e-4:
            selector.update_tree(action, 1)
            source_confidence = new_confidence
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)
        elif new_confidence > source_confidence + 1e-4:
            selector.update_tree(action, -1)
            shutil.copy(os.path.join(backup_dir, apk.name), work_apk)
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)
        else:
            selector.update_tree(action, 0)
            source_confidence = new_confidence
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)

    # Save results
    attack_time = time.time() - start_time
    
    if success:
        result_dir = Path(output_dir) / "success" / apk.name
        result_dir.mkdir(parents=True, exist_ok=True)
        
        with open(result_dir / "efficiency.txt", "w") as f:
            f.write(f"{attempt + 1}\n{attack_time}")
            
        shutil.copy(apk.location, result_dir / f"{apk.name}.source")
        shutil.copy(work_apk, result_dir / f"{apk.name}.adv")
        
        logging.info(f"Attack successful on {apk.name}")
    else:
        status = "modification_crash" if modification_crash else "fail"
        Path(output_dir, status, apk.name).mkdir(parents=True, exist_ok=True)
        logging.info(f"Attack {status} on {apk.name}")

    shutil.rmtree(tmp_dir)
