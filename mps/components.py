import os
import json
import random
import shutil
import traceback
import tempfile
import multiprocessing as mp
import logging

from androguard.misc import AnalyzeAPK
from androguard.core.androconf import show_logging
from settings import config
from utils import run_java_component
from tqdm import tqdm


def extract_apk_components(apk_path):
    """Extract components (activities, providers, receivers, services) from an APK."""
    print(f"Processing APK: {os.path.basename(apk_path)}")
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        return {
            "activities": a.get_activities(),
            "providers": a.get_providers(),
            "receivers": a.get_receivers(),
            "services": a.get_services(),
        }
    except Exception:
        print(f"Error processing APK: {os.path.basename(apk_path)}")
        traceback.print_exc()
        return None


def is_system_class(name):
    """Check if a class belongs to a system package."""
    system_packages = [
        "java.", "javax.", "android.", "androidx.", "dalvik.", "kotlin.", "kotlinx.",
        "junit.", "sun.", "org.w3c.", "org.xmlpull.", "org.xml.", "org.json.",
        "org.apache.", "com.google.", "com.android."
    ]
    return any(name.startswith(package) for package in system_packages)


def slice_apk(apk, component_name, output_dir):
    """Slice a specific component from an APK."""
    apk_path = os.path.join(config['source_apk_path'], f"{apk}.apk")
    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk_path))
    shutil.copy(apk_path, copy_apk_path)

    jar = config['slicer']
    args = [component_name, copy_apk_path, output_dir, config['android_sdk']]
    print(f"Extracting APK: {apk}, Component: {component_name}")
    out = run_java_component(jar, args, tmp_dir)

    if "Successfully" not in out:
        os.makedirs(os.path.join(output_dir, "failed"), exist_ok=True)

    shutil.rmtree(tmp_dir)


def get_candidate_benign_components(sampled_apk_num=100):
    """Extract and save candidate benign components from sampled APKs."""
    show_logging(logging.INFO)

    # Load metadata and filter benign APK paths
    with open(config['meta_data'], "r") as f:
        benign_apk_paths = [
            data['location'] for data in json.load(f) if data['label'] == 0
        ]
    benign_apk_paths = random.sample(
        benign_apk_paths, min(len(benign_apk_paths), sampled_apk_num)
    )

    # Initialize component data structures
    components = {"services": set(), "providers": set(), "receivers": set()}
    components_apk_map = {key: {} for key in components}

    # Extract components from APKs
    for apk in tqdm(benign_apk_paths, desc="Extracting APK Components"):
        res_data = extract_apk_components(apk)
        if not res_data:
            continue
        for component_type, component_classes in res_data.items():
            for component_class in filter(lambda c: not is_system_class(c), component_classes):
                components[component_type].add(component_class)
                components_apk_map[component_type].setdefault(component_class, []).append(
                    os.path.basename(apk)[:-4]
                )

    # Save extracted components to file
    os.makedirs("./slices_candidates", exist_ok=True)
    with open("./slices_candidates/candidates.json", "w") as f:
        json.dump(components_apk_map, f, indent=4)

    # Log summary and prepare slicing tasks
    logging.info(
        f"Sampled APKs: {sampled_apk_num}, "
        f"Services: {len(components['services'])}, "
        f"Providers: {len(components['providers'])}, "
        f"Receivers: {len(components['receivers'])}"
    )
    prepare_slicing_tasks(components_apk_map)


def prepare_slicing_tasks(components_apk_map):
    """Prepare and queue slicing tasks for APK components."""
    apk_list, component_list, output_list = [], [], []
    res_dir_path = config['slice_database']

    for component_type, components in components_apk_map.items():
        component_type_dir = os.path.join(res_dir_path, component_type)
        os.makedirs(component_type_dir, exist_ok=True)

        for component_class_name, candidate_apks in components.items():
            component_dir = os.path.join(
                component_type_dir, component_class_name)
            os.makedirs(component_dir, exist_ok=True)

            for apk in candidate_apks:
                apk_dir = os.path.join(component_dir, apk)
                os.makedirs(apk_dir, exist_ok=True)

                apk_list.append(apk)
                component_list.append(component_class_name)
                output_list.append(apk_dir)

    with mp.Pool(processes=10) as pool:
        pool.starmap(slice_apk, zip(apk_list, component_list, output_list))


def load_component_candidates():
    """Load successfully sliced components from the candidates JSON file."""
    sliced_components = {"services": {}, "providers": {}, "receivers": {}}

    with open("./slices_candidates/candidates.json", "r") as f:
        component_apk_dict = json.load(f)

    for component_type, components in component_apk_dict.items():
        for component_class_name, candidate_apks in components.items():
            for apk in candidate_apks:
                slice_res_dir = os.path.join(
                    config['slice_database'], component_type, component_class_name, apk
                )
                if not os.path.exists(os.path.join(slice_res_dir, "failed")):
                    sliced_components[component_type].setdefault(
                        component_class_name, []).append(apk)

    return sliced_components
