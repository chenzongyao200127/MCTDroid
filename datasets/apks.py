import os
from settings import config
import ujson as json
from defender.drebin import get_drebin_feature
from defender.mamadroid import get_mamadroid_feature
import multiprocessing as mp
from itertools import repeat
from utils import red
from androguard.core.androconf import show_logging
import logging
from tqdm import tqdm
import numpy as np
import random


class APK:
    """The APK data for feature extracting"""

    def __init__(self, path, label):
        self.name = os.path.basename(path)
        self.location = path
        self.label = label
        self.drebin_feature_path = os.path.join(
            config['saved_features'], 'drebin', self.name + ".json")
        self.mamadroid_feature_path = os.path.join(
            config['saved_features'], 'mamadroid', self.name + ".npz")
        self.drebin_feature = None
        self.mamadroid_family_feature = None

    def print_self(self):
        print("*" * 100)
        print(f"APK Name: {self.name}")
        print(f"Location: {self.location}")
        print(f"Label: {self.label}")
        print(f"Drebin Feature Path: {self.drebin_feature_path}")
        print(f"Mamadroid Feature Path: {self.mamadroid_feature_path}")
        print(
            f"Drebin Feature Loaded: {'Yes' if self.drebin_feature else 'No'}")
        print(
            f"Mamadroid Family Feature Loaded: {'Yes' if self.mamadroid_family_feature else 'No'}")
        print("*" * 100)

    def get_drebin_feature(self):
        """Extract the drebin feature"""
        if os.path.exists(self.drebin_feature_path):
            logging.info("Load APK: {}, drebin feature from file {}".format(
                self.name, self.drebin_feature_path))
            with open(self.drebin_feature_path, "rt") as f:
                self.drebin_feature = json.load(f)
        else:
            self.drebin_feature = get_drebin_feature(
                self.location, self.drebin_feature_path)

    def get_mamadroid_feature(self):
        """Extract the mamadroid feature"""
        if os.path.exists(self.mamadroid_feature_path):
            logging.info("Load APK: {}, mamadroid feature from file {}".format(
                self.name, self.mamadroid_feature_path))
            data = np.load(self.mamadroid_feature_path)
            self.mamadroid_family_feature = data['family_feature']
        else:
            self.mamadroid_family_feature = get_mamadroid_feature(
                self.location, self.mamadroid_feature_path)


class APKSET:
    """The Dataset for training the malware detection methods"""

    def __init__(self, meta_fp, name):
        self.name = name
        self.meta = None
        self.label = []
        self.total_set = []
        self.test_set = []
        self.train_idxs = []
        self.test_idxs = []
        self.load_data(meta_fp)

    def load_data(self, meta_fp):
        """Loading the total dataset"""
        with open(meta_fp, "r") as f:
            self.meta = json.load(f)

        for sample in self.meta:
            self.total_set.append(
                APK(
                    sample['location'],
                    sample['label'],
                ))
            self.label.append(int(sample['label']))

    def split_the_dataset(self):
        """Split the dataset"""
        benign_samples = [
            sample for sample in self.total_set if sample.label == 0]
        malicious_samples = [
            sample for sample in self.total_set if sample.label == 1]

        assert len(benign_samples) >= 10000 and len(
            malicious_samples) >= 10000, "Not enough samples."

        random.seed(42)

        train_benign = random.sample(benign_samples, 8000)
        test_benign = random.sample(
            [x for x in benign_samples if x not in train_benign], 2000)

        train_malicious = random.sample(malicious_samples, 8000)
        remaining_malicious = [
            x for x in malicious_samples if x not in train_malicious]

        test_malicious = random.sample(remaining_malicious, 2000)

        train_set = train_benign + train_malicious
        test_set = test_benign + test_malicious

        random.shuffle(train_set)
        random.shuffle(test_set)

        self.train_idxs = [self.total_set.index(
            sample) for sample in train_set]
        self.test_idxs = [self.total_set.index(sample) for sample in test_set]
        self.test_set = test_set

    def extract_the_feature(self, method):
        """Extract the training dataset feature"""
        if method == "mamadroid":
            if config['extract_feature']:
                show_logging(logging.INFO)

        unprocessed_apk_set = []
        for apk in self.total_set:
            if method == "drebin":
                if not os.path.exists(apk.drebin_feature_path):
                    unprocessed_apk_set.append(apk)
            elif method == "mamadroid":
                if not os.path.exists(apk.mamadroid_feature_path):
                    unprocessed_apk_set.append(apk)
        with mp.Pool(processes=config['nproc_feature']) as p:
            p.starmap(get_feature_wrapper, zip(
                unprocessed_apk_set, repeat(method)))

    def collect_the_feature(self, method):
        """Collect the features of all APKs into a single file for loading"""
        total_feature_fn = os.path.join(
            config['saved_features'], method + "_total", method + "_total_feature.json")
        if os.path.exists(total_feature_fn):
            return
        total_data = dict()
        dirname = os.path.join(config['saved_features'], method)
        apks = os.listdir(dirname)
        apks = sorted(apks)
        for apk in tqdm(apks):
            if method == "drebin":
                with open(os.path.join(dirname, apk), "r") as f:
                    data = json.load(f)
                    total_data[apk] = data
            elif method == "mamadroid":
                data = np.load(os.path.join(dirname, apk))
                if True not in np.isnan(data['family_feature']):
                    total_data[apk] = data['family_feature'].tolist()
        with open(total_feature_fn, "w") as f:
            json.dump(total_data, f)

    def load_the_feature(self, method):
        """Load the feature"""
        total_feature_fn = os.path.join(
            config['saved_features'], method + "_total", method + "_total_feature.json")
        if not os.path.exists(total_feature_fn):
            logging.error(
                red("The total feature is not exist, please extract the feature!"))
            exit(0)
        with open(total_feature_fn, "r") as f:
            total_feature = json.load(f)
        if method == "drebin":
            for apk in tqdm(self.total_set):
                apk.drebin_feature = total_feature[apk.name + ".json"]
        elif method == "mamadroid":
            for apk in tqdm(self.total_set):
                apk.mamadroid_family_feature = total_feature[apk.name + ".npz"]


def get_feature_wrapper(apk, method):
    """Wrapper function for parallel feature extraction"""
    if method == "drebin":
        apk.get_drebin_feature()
    elif method == "mamadroid":
        apk.get_mamadroid_feature()
