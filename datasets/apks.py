import os
from pathlib import Path
from typing import List, Dict, Optional
import ujson as json
import numpy as np
import random
import logging
import multiprocessing as mp
from itertools import repeat
from tqdm import tqdm
from dataclasses import dataclass
from functools import lru_cache

from settings import config
from defender.drebin import get_drebin_feature
from defender.mamadroid import get_mamadroid_feature
from utils import red
from androguard.core.androconf import show_logging


@dataclass
class APK:
    """Represents an APK file and its extracted features"""
    location: str
    label: int
    name: str = None
    drebin_feature: Optional[Dict] = None
    mamadroid_family_feature: Optional[np.ndarray] = None

    def __post_init__(self):
        self.name = os.path.basename(self.location)
        self._feature_dir = Path(config['saved_features'])
        self.drebin_feature_path = self._feature_dir / 'drebin' / f"{self.name}.json"
        self.mamadroid_feature_path = self._feature_dir / 'mamadroid' / f"{self.name}.npz"

    def print_self(self) -> None:
        """Print APK details for debugging"""
        details = [
            "*" * 100,
            f"APK Name: {self.name}",
            f"Location: {self.location}",
            f"Label: {self.label}",
            f"Drebin Feature Path: {self.drebin_feature_path}",
            f"Mamadroid Feature Path: {self.mamadroid_feature_path}",
            f"Drebin Feature Loaded: {'Yes' if self.drebin_feature else 'No'}",
            f"Mamadroid Family Feature Loaded: {'Yes' if self.mamadroid_family_feature else 'No'}",
            "*" * 100
        ]
        print("\n".join(details))

    @lru_cache(maxsize=None)
    def get_drebin_feature(self) -> None:
        """Extract or load cached drebin features"""
        if self.drebin_feature_path.exists():
            logging.info(f"Loading drebin feature for {self.name} from {self.drebin_feature_path}")
            self.drebin_feature = json.load(self.drebin_feature_path.open())
        else:
            self.drebin_feature = get_drebin_feature(self.location, str(self.drebin_feature_path))

    @lru_cache(maxsize=None) 
    def get_mamadroid_feature(self) -> None:
        """Extract or load cached mamadroid features"""
        if self.mamadroid_feature_path.exists():
            logging.info(f"Loading mamadroid feature for {self.name} from {self.mamadroid_feature_path}")
            self.mamadroid_family_feature = np.load(self.mamadroid_feature_path)['family_feature']
        else:
            self.mamadroid_family_feature = get_mamadroid_feature(self.location, str(self.mamadroid_feature_path))


class APKSET:
    """Dataset manager for malware detection"""
    def __init__(self, meta_fp: str, name: str):
        self.name = name
        self.total_set: List[APK] = []
        self.test_set: List[APK] = []
        self.train_idxs: List[int] = []
        self.test_idxs: List[int] = []
        self._load_data(meta_fp)
        
    @property
    def label(self) -> List[int]:
        return [apk.label for apk in self.total_set]

    def _load_data(self, meta_fp: str) -> None:
        """Load dataset from metadata file"""
        with open(meta_fp) as f:
            meta = json.load(f)
            
        self.total_set = [APK(sample['location'], int(sample['label'])) for sample in meta]

    def split_the_dataset(self, train_size: int = 8000, test_size: int = 2000, seed: int = 42) -> None:
        """Split dataset into training and test sets with balanced labels"""
        random.seed(seed)
        
        benign = [s for s in self.total_set if s.label == 0]
        malicious = [s for s in self.total_set if s.label == 1]
        
        if len(benign) < train_size + test_size or len(malicious) < train_size + test_size:
            raise ValueError("Insufficient samples for requested split sizes")

        train_benign = random.sample(benign, train_size)
        test_benign = random.sample([x for x in benign if x not in train_benign], test_size)
        
        train_malicious = random.sample(malicious, train_size)
        test_malicious = random.sample([x for x in malicious if x not in train_malicious], test_size)

        train_set = train_benign + train_malicious
        test_set = test_benign + test_malicious
        random.shuffle(train_set)
        random.shuffle(test_set)

        self.train_idxs = [self.total_set.index(s) for s in train_set]
        self.test_idxs = [self.total_set.index(s) for s in test_set]
        self.test_set = test_set

    def extract_the_feature(self, method: str) -> None:
        """Extract features in parallel for unprocessed APKs"""
        if method == "mamadroid" and config['extract_feature']:
            show_logging(logging.INFO)

        feature_paths = {'drebin': 'drebin_feature_path', 'mamadroid': 'mamadroid_feature_path'}
        if method not in feature_paths:
            raise ValueError(f"Unsupported feature method: {method}")

        unprocessed = [apk for apk in self.total_set 
                      if not Path(getattr(apk, feature_paths[method])).exists()]

        if unprocessed:
            with mp.Pool(processes=config['nproc_feature']) as pool:
                pool.starmap(get_feature_wrapper, zip(unprocessed, repeat(method)))

    def collect_the_feature(self, method: str) -> None:
        """Aggregate extracted features into a single file"""
        total_feature_path = Path(config['saved_features']) / f"{method}_total" / f"{method}_total_feature.json"
        if total_feature_path.exists():
            return

        feature_dir = Path(config['saved_features']) / method
        total_data = {}

        for apk_path in tqdm(sorted(feature_dir.glob('*'))):
            if method == "drebin":
                total_data[apk_path.name] = json.load(apk_path.open())
            elif method == "mamadroid":
                data = np.load(apk_path)
                if not np.isnan(data['family_feature']).any():
                    total_data[apk_path.name] = data['family_feature'].tolist()

        total_feature_path.parent.mkdir(exist_ok=True)
        json.dump(total_data, total_feature_path.open('w'))

    def load_the_feature(self, method: str) -> None:
        """Load aggregated features into APK objects"""
        total_feature_path = Path(config['saved_features']) / f"{method}_total" / f"{method}_total_feature.json"
        
        if not total_feature_path.exists():
            logging.error(red("Total feature file not found. Please extract features first."))
            exit(1)

        total_feature = json.load(total_feature_path.open())
        
        for apk in tqdm(self.total_set):
            feature_key = f"{apk.name}.{'json' if method == 'drebin' else 'npz'}"
            if method == "drebin":
                apk.drebin_feature = total_feature[feature_key]
            else:
                apk.mamadroid_family_feature = total_feature[feature_key]


def get_feature_wrapper(apk: APK, method: str) -> None:
    """Parallel feature extraction wrapper"""
    feature_methods = {
        "drebin": APK.get_drebin_feature,
        "mamadroid": APK.get_mamadroid_feature
    }
    feature_methods[method](apk)
