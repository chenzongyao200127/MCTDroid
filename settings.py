import os

_project_path = '/disk2/chenzy/MCTDroid/'


def _project(base):
    return os.path.join(_project_path, base)


config = {
    # Experiment settings
    'saved_models': _project('model_results/models'),
    'saved_features': _project('model_results/features'),
    'meta_data': _project('meta_info/dataset/total_apks_data.json'),
    'android_sdk': '/disk2/chenzy/android-sdk/',
    'tmp_dir': _project('tmp'),
    'results_dir': _project('results'),
    'source_apk_path': '/disk2/Androzoo/SelectedBenign',
    'slice_database': _project('slices_database'),
    "resigner": _project("java-components/apk-signer.jar"),

    # drebin
    'drebin_feature_extractor': _project('drebin-feature-extractor'),
    'drebin_api_path': _project('drebin-feature-extractor/APIcalls.txt'),

    # mamadroid
    'family_list': _project('meta_info/mamadroid/families.txt'),
    'package_list': _project('meta_info/mamadroid/packages.txt'),

    # Modifier
    "slicer": _project('java-components/slicer.jar'),
    "manifest": _project('java-components/manifest.jar'),
    "injector": _project('java-components/injector.jar'),

    # Misc
    'nproc_feature': 20,
    'nproc_slicer': 10,
    'nproc_attacker': 10,
    'sign': False,
    'extract_feature': False,  # Extract the feature
    'serial': False,  # Attack in serial
}
