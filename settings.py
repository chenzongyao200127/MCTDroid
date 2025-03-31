import os

# Constants
PROJECT_PATH = "/mnt/sdb2/czy/MCTDroid/"
ANDROID_SDK_PATH = '/mnt/sdb2/andro_apk/android-sdk/'
SOURCE_APK_PATH = '/mnt/sdb2/andro_apk/Drebin/Benign'


def project(base):
    return os.path.join(PROJECT_PATH, base)


config = {
    'saved_models': project('model_results/models'),
    'saved_features': project('model_results/features'),
    'meta_data': project('meta_info/dataset/total_apks_data.json'),
    'android_sdk': ANDROID_SDK_PATH,
    'tmp_dir': project('/mnt/sdb2/andro_apk/tmp'),
    'results_dir': project('results'),
    'source_apk_path': SOURCE_APK_PATH,
    'slice_database': project('slices_database'),
    'resigner': project('java-components/apk-signer.jar'),

    'drebin_feature_extractor': project('drebin-feature-extractor'),
    'drebin_api_path': project('drebin-feature-extractor/APIcalls.txt'),

    'family_list': project('meta_info/mamadroid/families.txt'),
    'package_list': project('meta_info/mamadroid/packages.txt'),

    'slicer': project('java-components/slicer.jar'),
    'manifest': project('java-components/manifest.jar'),
    'injector': project('java-components/injector.jar'),

    'nproc_feature': 30,
    'nproc_slicer': 10,
    'nproc_attacker': 10,
    'sign': False,
    'extract_feature': False,
    'serial': False,
}
