import os
import logging
import random
from itertools import repeat
import multiprocessing as mp

import numpy as np
from tqdm import tqdm
import ujson as json

from settings import config
from utils import red
from defender.drebin import get_drebin_feature
from defender.mamadroid import get_mamadroid_feature
from defender.apigraph import get_apigraph_feature
from defender.vae_fd import get_vae_fd_feature
from androguard.core.androconf import show_logging


class APK:
    """The APK data for feature extracting"""

    def __init__(self, path, label, name, time):
        self.name = name
        self.location = path
        self.label = label
        self.time = time  # The time of the APKs
        
        # Define feature paths
        features_dir = config['saved_features']
        self.drebin_feature_path = os.path.join(features_dir, 'drebin', f"{self.name}.json")
        self.apigraph_feature_path = os.path.join(features_dir, 'apigraph', f"{self.name}.json")
        self.mamadroid_feature_path = os.path.join(features_dir, 'mamadroid', f"{self.name}.npz")
        self.vae_fd_feature_path = os.path.join(features_dir, 'vae_fd', f"{self.name}.npz")
        
        # Initialize feature containers
        self.drebin_feature = None
        self.apigraph_feature = None
        self.mamadroid_family_feature = None
        self.vae_fd_feature = None

    def get_drebin_feature(self):
        """Extract the drebin feature"""
        if os.path.exists(self.drebin_feature_path):
            logging.info(f"Load APK: {self.name}, drebin feature from file {self.drebin_feature_path}")
            with open(self.drebin_feature_path, "rt") as f:
                self.drebin_feature = json.load(f)
        else:
            self.drebin_feature = get_drebin_feature(self.location, self.drebin_feature_path)

    def get_apigraph_feature(self):
        """Extract the apigraph feature"""
        if os.path.exists(self.apigraph_feature_path):
            logging.info(f"Load APK: {self.name}, apigraph feature from file {self.apigraph_feature_path}")
            with open(self.apigraph_feature_path, "rt") as f:
                self.apigraph_feature = json.load(f)
        else:
            self.apigraph_feature = get_apigraph_feature(self.location, self.apigraph_feature_path)

    def get_mamadroid_feature(self):
        """Extract the mamadroid feature"""
        if os.path.exists(self.mamadroid_feature_path):
            logging.info(f"Load APK: {self.name}, mamadroid feature from file {self.mamadroid_feature_path}")
            data = np.load(self.mamadroid_feature_path)
            self.mamadroid_family_feature = data['family_feature']
        else:
            self.mamadroid_family_feature = get_mamadroid_feature(self.location, self.mamadroid_feature_path)

    def get_vae_fd_feature(self):
        """Extract the vae_fd feature"""
        if os.path.exists(self.vae_fd_feature_path):
            logging.info(f"Load APK: {self.name}, vae_fd feature from file {self.vae_fd_feature_path}")
            data = np.load(self.vae_fd_feature_path)
            self.vae_fd_feature = data['vae_fd_feature']
        else:
            self.vae_fd_feature = get_vae_fd_feature(self.location, self.vae_fd_feature_path)

class APKSET:
    """The Dataset for training the malware detection methods"""

    def __init__(self, meta_fp, dataset_name):
        self.name = dataset_name
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
                    sample['name'],
                    time=os.path.getmtime(sample['location']),
                    )
            )
            self.label.append(int(sample['label']))
            
    def split_the_dataset(self, train_ratio=0.8):
        """
        Split the dataset into training and testing sets.
        
        Both training and testing sets maintain a 4:1 ratio of benign to malicious samples.
        
        Args:
            train_ratio: Ratio of training data to total data (default: 0.8)
        """
        # Separate benign and malicious samples
        benign_samples = [sample for sample in self.total_set if sample.label == 0]
        malicious_samples = [sample for sample in self.total_set if sample.label == 1]

        # Set seed for reproducibility
        random.seed(42)
        
        # 4:1 ratio means 80% benign, 20% malicious
        benign_ratio = 0.8
        
        # Calculate maximum samples we can use while maintaining the benign:malicious ratio
        total_usable = min(
            len(benign_samples) / benign_ratio, 
            len(malicious_samples) / (1 - benign_ratio)
        )
        total_usable = int(total_usable)
        
        # Calculate exact numbers for each category
        total_benign = int(total_usable * benign_ratio)
        total_malicious = total_usable - total_benign
        
        # Calculate train/test split sizes
        train_benign_size = int(total_benign * train_ratio)
        test_benign_size = total_benign - train_benign_size
        
        train_malicious_size = int(total_malicious * train_ratio)
        test_malicious_size = total_malicious - train_malicious_size
        
        # Sample the datasets
        selected_benign = random.sample(benign_samples, total_benign)
        selected_malicious = random.sample(malicious_samples, int(total_malicious))
        
        # Split into train and test sets
        train_benign = selected_benign[:train_benign_size]
        test_benign = selected_benign[train_benign_size:]
        
        train_malicious = selected_malicious[:train_malicious_size]
        test_malicious = selected_malicious[train_malicious_size:]
        
        # Combine and shuffle
        train_set = train_benign + train_malicious
        test_set = test_benign + test_malicious
        
        random.shuffle(train_set)
        random.shuffle(test_set)
        
        # Store results
        self.train_idxs = [self.total_set.index(sample) for sample in train_set]
        self.test_idxs = [self.total_set.index(sample) for sample in test_set]
        self.test_set = test_set

    def extract_the_feature(self, method):
        """Extract the training dataset feature"""
        if method == "mamadroid" or method == "vae_fd":
            if config['extract_feature']:
                show_logging(logging.INFO)

        unprocessed_apk_set = []
        for apk in self.total_set:
            if method == "drebin":
                if not os.path.exists(apk.drebin_feature_path):
                    unprocessed_apk_set.append(apk)
            elif method == "apigraph":
                if not os.path.exists(apk.apigraph_feature_path):
                    unprocessed_apk_set.append(apk)
            elif method == "mamadroid":
                if not os.path.exists(apk.mamadroid_feature_path):
                    unprocessed_apk_set.append(apk)
            elif method == "vae_fd":
                if not os.path.exists(apk.vae_fd_feature_path):
                    unprocessed_apk_set.append(apk)
        with mp.Pool(processes=config['nproc_feature']) as p:
            p.starmap(get_feature_wrapper, zip(unprocessed_apk_set, repeat(method)))

    def collect_the_feature(self, method):
        """Collect the features of all APKs into a single file for loading"""
        total_feature_fn = os.path.join(config['saved_features'], method + "_total", method + "_total_feature.json")
        if os.path.exists(total_feature_fn):
            return
        total_data = dict()
        dirname = os.path.join(config['saved_features'], method)
        apks = os.listdir(dirname)
        apks = sorted(apks)
        for apk in tqdm(apks):
            if method == "apigraph" or method == "drebin":
                with open(os.path.join(dirname, apk), "r") as f:
                    data = json.load(f)
                    total_data[apk] = data
            elif method == "mamadroid":
                data = np.load(os.path.join(dirname, apk))
                if True not in np.isnan(data['family_feature']):
                    total_data[apk] = data['family_feature'].tolist()
            else:
                data = np.load(os.path.join(dirname, apk))
                total_data[apk] = data['vae_fd_feature'].tolist()
        with open(total_feature_fn, "w") as f:
            json.dump(total_data, f)
            
    def load_the_feature(self, method):
        """Load the feature"""
        total_feature_fn = os.path.join(config['saved_features'], method + "_total", method + "_total_feature.json")
        if not os.path.exists(total_feature_fn):
            logging.error(red("The total feature is not exist, please extract the feature!"))
            exit(0)
        with open(total_feature_fn, "r") as f:
            total_feature = json.load(f)
        if method == "drebin":
            for apk in tqdm(self.total_set):
                apk.drebin_feature = total_feature[apk.name + ".json"]
        elif method == "mamadroid":
            for apk in tqdm(self.total_set):
                apk.mamadroid_family_feature = total_feature[apk.name + ".npz"]
        elif method == "apigraph":
            for apk in tqdm(self.total_set):
                apk.apigraph_feature = total_feature[apk.name + ".json"]
        elif method == "vae_fd":
            for apk in tqdm(self.total_set):
                apk.vae_fd_feature = total_feature[apk.name + ".npz"]


def get_feature_wrapper(apk, method):
    """Wrapper function for parallel feature extraction"""
    if method == "drebin":
        apk.get_drebin_feature()
    elif method == "mamadroid":
        apk.get_mamadroid_feature()
    elif method == "apigraph":
        apk.get_apigraph_feature()
    elif method == "vae_fd":
        apk.get_vae_fd_feature()

