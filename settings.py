import os
from pathlib import Path

# Constants
PROJECT_PATH = Path("/mnt/sdb2/czy/MCTDroid/")
ANDROID_SDK_PATH = Path('/mnt/sdb2/andro_apk/android-sdk/')
SOURCE_APK_PATH = Path('/mnt/sdb2/andro_apk/Drebin/Benign')

# Component paths
JAVA_COMPONENTS = 'java-components'
MODEL_RESULTS = 'model_results'
META_INFO = 'meta_info'


def project(base):
    """Join base path with project path"""
    return PROJECT_PATH / base


# Configuration dictionary with organized sections
config = {
    # Storage paths
    'saved_models': project(f'{MODEL_RESULTS}/models'),
    'saved_features': project(f'{MODEL_RESULTS}/features'),
    'results_dir': project('results'),
    'slice_database': project('slices_database'),
    'tmp_dir': Path('/mnt/sdb2/andro_apk/tmp'),
    
    # Source paths
    'meta_data': project(f'{META_INFO}/dataset/dataset_meta_data.json'),
    'android_sdk': ANDROID_SDK_PATH,
    'source_apk_path': SOURCE_APK_PATH,
    
    # Java components
    'resigner': project(f'{JAVA_COMPONENTS}/apk-signer.jar'),
    'slicer': project(f'{JAVA_COMPONENTS}/slicer.jar'),
    'manifest': project(f'{JAVA_COMPONENTS}/manifest.jar'),
    'injector': project(f'{JAVA_COMPONENTS}/injector.jar'),
    
    # Drebin feature extraction
    'drebin_feature_extractor': project('drebin-feature-extractor'),
    'drebin_api_path': project('drebin-feature-extractor/APIcalls.txt'),
    
    # Mamadroid paths
    'family_list': project(f'{META_INFO}/mamadroid/families.txt'),
    'package_list': project(f'{META_INFO}/mamadroid/packages.txt'),
    
    # Process configuration
    'nproc_feature': 40,
    'nproc_slicer': 10,
    'nproc_attacker': 10,
    
    # Flags
    'sign': False,
    'extract_feature': True,
    'serial': False,
}
