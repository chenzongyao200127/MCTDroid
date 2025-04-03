import os
from pathlib import Path

# Constants
PROJECT_PATH = str(Path("/disk2/chenzy/MCTDroid/"))
ANDROID_SDK_PATH = str('/disk2/chenzy/android-sdk/')
SOURCE_BENIGN_APK_PATH = str(
    Path('/disk2/Androzoo/SelectedBenign'))
SOURCE_MALWARE_APK_PATH = str(
    Path('/disk2/Androzoo/SelectedMalware'))

# Component paths
JAVA_COMPONENTS = 'java-components'
MODEL_RESULTS = 'model_results'
META_INFO = 'meta_info'


def project(base):
    """Join base path with project path"""
    return os.path.join(PROJECT_PATH, base)


# Configuration dictionary with organized sections
config = {
    # Storage paths
    'saved_models': project(f'{MODEL_RESULTS}/models'),
    'saved_features': project(f'{MODEL_RESULTS}/features'),
    'results_dir': project('results'),
    'slice_database': project('slices_database'),
    'tmp_dir': str(Path('/disk2/Androzoo/tmp')),

    # Source paths
    'meta_data': project(f'{META_INFO}/dataset/dataset_meta_data.json'),
    'android_sdk': ANDROID_SDK_PATH,
    'source_benign_apk_path': SOURCE_BENIGN_APK_PATH,
    'source_malware_apk_path': SOURCE_MALWARE_APK_PATH,

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

    # apigraph clustering info
    "clustering_info": project(f'{META_INFO}/apigraph/method_cluster_mapping_2000.pkl'),

    # vae-fd
    "vae_permissions": project(f'{META_INFO}/vae/list_total_permissions.txt'),
    "vae_actions": project(f'{META_INFO}/vae/list_total_actions.txt'),
    "vae_apis": project(f'{META_INFO}/vae/list_total_apis.txt'),

    # Process configuration
    'nproc_feature': 20,
    'nproc_slicer': 10,
    'nproc_attacker': 10,

    # Flags
    'sign': False,
    'extract_feature': False,  # only when the feature extractor is not in the pipeline
    'serial': False,
}
