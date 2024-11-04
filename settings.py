import os

class Config:
    _project_path = '/disk2/chenzy/MCTDroid/'

    @classmethod
    def _project(cls, base):
        return os.path.join(cls._project_path, base)

    saved_models = _project.__func__('model_results/models')
    saved_features = _project.__func__('model_results/features')
    meta_data = _project.__func__('meta_info/dataset/total_apks_data.json')
    android_sdk = '/disk2/chenzy/android-sdk/'
    tmp_dir = _project.__func__('tmp')
    results_dir = _project.__func__('results')
    source_apk_path = '/disk2/Androzoo/SelectedBenign'
    slice_database = _project.__func__('slices_database')
    resigner = _project.__func__('java-components/apk-signer.jar')

    # drebin
    drebin_feature_extractor = _project.__func__('drebin-feature-extractor')
    drebin_api_path = _project.__func__('drebin-feature-extractor/APIcalls.txt')

    # mamadroid
    family_list = _project.__func__('meta_info/mamadroid/families.txt')
    package_list = _project.__func__('meta_info/mamadroid/packages.txt')

    # Modifier
    slicer = _project.__func__('java-components/slicer.jar')
    manifest = _project.__func__('java-components/manifest.jar')
    injector = _project.__func__('java-components/injector.jar')

    # Misc
    nproc_feature = 20
    nproc_slicer = 10
    nproc_attacker = 10
    sign = False
    extract_feature = False  # Extract the feature
    serial = False  # Attack in serial

config = Config()
