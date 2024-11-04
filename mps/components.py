import os
import json
import random
import shutil
import traceback
import multiprocessing as mp
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Optional
from androguard.misc import AnalyzeAPK
from androguard.core.androconf import show_logging
from tqdm import tqdm
from settings import config
from utils import run_java_component


def extract_apk_components(apk_path: str) -> Optional[Dict[str, List[str]]]:
    """
    Extract components (activities, providers, receivers, services) from an APK file.
    
    Args:
        apk_path: Path to the APK file
        
    Returns:
        Dictionary containing lists of components, or None if extraction fails
    """
    print(f"Processing APK: {Path(apk_path).name}")
    
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        return {
            "activities": a.get_activities(),
            "providers": a.get_providers(), 
            "receivers": a.get_receivers(),
            "services": a.get_services()
        }
    except Exception as e:
        print(f"Error processing APK {Path(apk_path).name}: {e}")
        traceback.print_exc()
        return None


def is_system_class(class_name: str) -> bool:
    """
    Check if a class belongs to the Android system packages.
    
    Args:
        class_name: Fully qualified class name
        
    Returns:
        True if class belongs to system packages, False otherwise
    """
    SYSTEM_PACKAGES = {
        "java.", "javax.", "android.", "androidx.", "dalvik.", 
        "kotlin.", "kotlinx.", "junit.", "sun.", "org.w3c.",
        "org.xmlpull.", "org.xml.", "org.json.", "org.apache.",
        "com.google.", "com.android."
    }
    return any(class_name.startswith(pkg) for pkg in SYSTEM_PACKAGES)


def slice_apk(apk_name: str, component_name: str, output_dir: str) -> None:
    """
    Slice an APK to extract a specific component.
    
    Args:
        apk_name: Name of the APK file (without extension)
        component_name: Name of component to extract
        output_dir: Directory to store slicing results
    """
    apk_path = Path(config['source_apk_path']) / f"{apk_name}.apk"
    
    # Create temporary working directory
    with tempfile.TemporaryDirectory(dir=config['tmp_dir']) as tmp_dir:
        tmp_dir = Path(tmp_dir)
        copy_apk_path = tmp_dir / apk_path.name
        
        # Copy APK to temp directory
        shutil.copy(apk_path, copy_apk_path)
        
        print(f"Extracting component {component_name} from APK {apk_name}")
        
        # Run Java slicer
        args = [component_name, str(copy_apk_path), output_dir, config['android_sdk']]
        result = run_java_component(config['slicer'], args, str(tmp_dir))
        
        if "Successfully" not in result:
            Path(output_dir, "failed").mkdir(exist_ok=True)


def get_candidate_benign_components(sample_size: int = 100) -> None:
    """
    Extract and process components from benign APKs to create a component pool.
    
    Args:
        sample_size: Number of APKs to sample
    """
    show_logging(logging.INFO)
    
    # Load and sample benign APKs
    with open(config['meta_data']) as f:
        meta = json.load(f)
    
    benign_apks = [data['location'] for data in meta if data['label'] == 0]
    sampled_apks = random.sample(benign_apks, min(len(benign_apks), sample_size))
    
    # Initialize component tracking
    components_by_type: Dict[str, Dict[str, List[str]]] = {
        "services": {}, "providers": {}, "receivers": {}
    }
    unique_components: Dict[str, Set[str]] = {
        "services": set(), "providers": set(), "receivers": set()
    }
    
    # Process APKs
    for apk in tqdm(sampled_apks, desc="Extracting APK Components"):
        components = extract_apk_components(apk)
        if components:
            process_components(components, unique_components, components_by_type, apk)
    
    # Save results
    save_dir = Path("./slices_candidates")
    save_dir.mkdir(exist_ok=True)
    with open(save_dir / "candidates.json", "w") as f:
        json.dump(components_by_type, f, indent=4)
        
    print_component_stats(sample_size, unique_components)
    prepare_and_queue_slicing_tasks(components_by_type)


def process_components(
    components: Dict[str, List[str]],
    unique_components: Dict[str, Set[str]], 
    components_by_type: Dict[str, Dict[str, List[str]]],
    apk_path: str
) -> None:
    """Process extracted components and update tracking dictionaries."""
    apk_name = Path(apk_path).stem
    
    for comp_type in ["services", "providers", "receivers"]:
        for component in components.get(comp_type, []):
            if not is_system_class(component):
                unique_components[comp_type].add(component)
                components_by_type[comp_type].setdefault(component, []).append(apk_name)


def print_component_stats(sample_size: int, unique_components: Dict[str, Set[str]]) -> None:
    """Print summary statistics of extracted components."""
    print(
        f"Sample size: {sample_size}, "
        f"Services: {len(unique_components['services'])}, "
        f"Providers: {len(unique_components['providers'])}, "
        f"Receivers: {len(unique_components['receivers'])}"
    )


def prepare_and_queue_slicing_tasks(components_by_type: Dict[str, Dict[str, List[str]]]) -> None:
    """
    Prepare directories and execute slicing tasks in parallel.
    
    Args:
        components_by_type: Mapping of component types to their APKs
    """
    slice_tasks = []
    slice_base = Path(config['slice_database'])
    
    for comp_type, components in components_by_type.items():
        type_dir = slice_base / comp_type
        
        for comp_name, apks in components.items():
            comp_dir = type_dir / comp_name
            
            for apk in apks:
                output_dir = comp_dir / apk
                output_dir.mkdir(parents=True, exist_ok=True)
                slice_tasks.append((apk, comp_name, str(output_dir)))
    
    with mp.Pool(processes=10) as pool:
        pool.starmap(slice_apk, slice_tasks)


def load_component_candidates() -> Dict[str, Dict[str, List[str]]]:
    """
    Load and validate previously sliced components.
    
    Returns:
        Dictionary mapping component types to their successfully sliced instances
    """
    sliced_components = {
        'services': {}, 'providers': {}, 'receivers': {}
    }
    
    candidates_path = Path("./slices_candidates/candidates.json")
    with open(candidates_path) as f:
        component_apk_dict = json.load(f)
    
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
