import os
import json
import random
import shutil
import tempfile
import traceback
import multiprocessing as mp
import logging
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from androguard.misc import AnalyzeAPK
from androguard.core.androconf import show_logging
from tqdm import tqdm
from settings import config
from utils import run_java_component

# Cache system package checks
SYSTEM_PACKAGES = frozenset([
    "java.", "javax.", "android.", "androidx.", "dalvik.",
    "kotlin.", "kotlinx.", "junit.", "sun.", "org.w3c.",
    "org.xmlpull.", "org.xml.", "org.json.", "org.apache.",
    "com.google.", "com.android."
])


@lru_cache(maxsize=1024)
def is_system_class(class_name: str) -> bool:
    return any(class_name.startswith(pkg) for pkg in SYSTEM_PACKAGES)


def extract_apk_components(apk_path: str) -> Optional[Dict[str, List[str]]]:
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        return {
            "activities": a.get_activities(),
            "providers": a.get_providers(),
            "receivers": a.get_receivers(),
            "services": a.get_services()
        }
    except Exception as e:
        logging.error(f"Error processing APK {Path(apk_path).name}: {e}")
        logging.debug(traceback.format_exc())
        return None


def slice_apk(apk_name: str, component_name: str, output_dir: str) -> None:
    apk_path = Path(config['source_apk_path']) / f"{apk_name}.apk"
    output_path = Path(output_dir)

    if not apk_path.exists():
        logging.error(f"APK not found: {apk_path}")
        return

    if list(output_path.glob('*')):
        logging.info(f"Output directory not empty, skipping: {output_dir}")
        return

    with tempfile.TemporaryDirectory(dir=config['tmp_dir']) as tmp_dir:
        tmp_path = Path(tmp_dir) / apk_path.name
        shutil.copy(apk_path, tmp_path)

        args = [component_name, str(
            tmp_path), output_dir, config['android_sdk']]
        result = run_java_component(config['slicer'], args, tmp_dir)

        if "Successfully" not in result:
            (output_path / "failed").mkdir(exist_ok=True)


def process_components(
    components: Dict[str, List[str]],
    unique_components: Dict[str, Set[str]],
    components_by_type: Dict[str, Dict[str, List[str]]],
    apk_path: str
) -> None:
    apk_name = Path(apk_path).stem

    for comp_type in ("services", "providers", "receivers"):
        for component in components.get(comp_type, []):
            if not is_system_class(component):
                unique_components[comp_type].add(component)
                components_by_type[comp_type].setdefault(
                    component, []).append(apk_name)


def get_candidate_benign_components(sample_size: int = 100) -> None:
    show_logging(logging.INFO)

    with open(config['meta_data']) as f:
        meta = json.load(f)

    benign_apks = [data['location'] for data in meta if data['label'] == 0]
    sampled_apks = random.sample(
        benign_apks, min(len(benign_apks), sample_size))

    components_by_type: Dict[str, Dict[str, List[str]]] = {
        "services": {}, "providers": {}, "receivers": {}
    }
    unique_components: Dict[str, Set[str]] = {
        "services": set(), "providers": set(), "receivers": set()
    }

    with mp.Pool() as pool:
        results = list(tqdm(
            pool.imap(extract_apk_components, sampled_apks),
            total=len(sampled_apks),
            desc="Extracting APK Components"
        ))

    for apk, components in zip(sampled_apks, results):
        if components:
            process_components(components, unique_components,
                               components_by_type, apk)

    save_dir = Path("./slices_candidates")
    save_dir.mkdir(exist_ok=True)
    with open(save_dir / "candidates.json", "w") as f:
        json.dump(components_by_type, f, indent=4)

    logging.info(
        f"Sample size: {sample_size}, "
        f"Services: {len(unique_components['services'])}, "
        f"Providers: {len(unique_components['providers'])}, "
        f"Receivers: {len(unique_components['receivers'])}"
    )

    prepare_and_queue_slicing_tasks(components_by_type)


def prepare_and_queue_slicing_tasks(components_by_type: Dict[str, Dict[str, List[str]]]) -> None:
    slice_tasks = []
    slice_base = Path(config['slice_database'])

    for comp_type, components in components_by_type.items():
        type_dir = slice_base / comp_type
        for comp_name, apks in components.items():
            comp_dir = type_dir / comp_name
            for apk in apks:
                output_dir = comp_dir / apk
                output_dir.mkdir(parents=True, exist_ok=True)
                apk_str = str(apk)
                comp_name_str = str(comp_name)
                output_dir_str = str(output_dir.resolve())
                slice_tasks.append((apk_str, comp_name_str, output_dir_str))

    with mp.Pool() as pool:
        list(tqdm(
            pool.starmap(slice_apk, slice_tasks),
            total=len(slice_tasks),
            desc="Slicing APKs"
        ))


@lru_cache(maxsize=1)
def load_component_candidates() -> Dict[str, Dict[str, List[str]]]:
    sliced_components = {
        'services': {}, 'providers': {}, 'receivers': {}
    }

    try:
        with open("./slices_candidates/candidates.json") as f:
            component_apk_dict = json.load(f)
    except FileNotFoundError:
        logging.error("candidates.json not found")
        return sliced_components

    slice_base = Path(config['slice_database'])

    for comp_type, components in component_apk_dict.items():
        for comp_name, apks in components.items():
            successful_apks = [
                apk for apk in apks
                if not (slice_base / comp_type / comp_name / apk / "failed").exists()
            ]

            if successful_apks:
                sliced_components[comp_type][comp_name] = successful_apks

    return sliced_components
