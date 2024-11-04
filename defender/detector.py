import os
import numpy as np
import pickle
import logging
from sklearn.feature_extraction import DictVectorizer
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier 
from sklearn.ensemble import RandomForestClassifier
from utils import blue, green
from lib.mlp import MLP
from pathlib import Path
from typing import List, Optional, Union, Dict


class Detector:
    def __init__(self, name: str, saving_path: str, feature: str, classifier: str) -> None:
        """Initialize detector with configuration parameters.
        
        Args:
            name: Name of the detector model
            saving_path: Directory to save model files
            feature: Feature extraction method to use
            classifier: ML classifier type to use
        """
        self.name = f"{name}.model"
        self.mlp_epochs = 1
        self.saving_path = self._build_saving_path(saving_path, classifier)
        self.feature = feature
        self.classifier = classifier
        
        # Initialize model components
        self.clf: Optional[Union[LinearSVC, KNeighborsClassifier, RandomForestClassifier, MLP]] = None
        self.vec: Optional[DictVectorizer] = None
        
        # Initialize dataset arrays
        self.X: Optional[np.ndarray] = None 
        self.X_train: Optional[np.ndarray] = None
        self.y_train: Optional[np.ndarray] = None
        self.X_test: Optional[np.ndarray] = None
        self.y_test: Optional[np.ndarray] = None

    def _build_saving_path(self, base_path: str, classifier: str) -> str:
        """Build model save path based on classifier type."""
        if classifier == "mlp":
            return os.path.join(base_path, f"{self.name}_{self.mlp_epochs}")
        return os.path.join(base_path, self.name)

    def _extract_features(self, dataset) -> np.ndarray:
        """Extract features based on specified feature type."""
        if self.feature == "drebin":
            features = [apk.drebin_feature for apk in dataset.total_set]
            self.train_features = [dataset.total_set[idx].drebin_feature for idx in dataset.train_idxs]
            return features
        elif self.feature == "mamadroid":
            return [np.asarray(apk.mamadroid_family_feature) for apk in dataset.total_set]
        raise ValueError(f"Unknown feature type: {self.feature}")

    def _load_or_create_vectorizer(self, X: List[Dict]) -> np.ndarray:
        """Load existing vectorizer or create new one and transform features."""
        vec_path = Path(f"{self.saving_path}.vec")
        if vec_path.exists():
            logging.debug(blue(f'Loading vectorizer from {vec_path}...'))
            with open(vec_path, "rb") as f:
                self.vec = pickle.load(f)
            return self.vec.transform(X)
        
        self.vec = DictVectorizer()
        self.vec.fit_transform(self.train_features)
        return self.vec.transform(X)

    def _initialize_classifier(self):
        """Initialize the ML classifier based on specified type."""
        if self.classifier == "svm":
            return LinearSVC(C=1, verbose=True)
        elif self.classifier == "3nn":
            return KNeighborsClassifier(n_neighbors=3)
        elif self.classifier == "mlp":
            return MLP(input_dim=self.X_train[0].shape[-1], epochs=self.mlp_epochs)
        elif self.classifier == "rf":
            return RandomForestClassifier(max_depth=8, random_state=0)
        raise ValueError(f"Unknown classifier type: {self.classifier}")

    def build_classifier(self, dataset, save: bool = True) -> None:
        """Build and train the classifier on the dataset."""
        # Extract features
        X = self._extract_features(dataset)
        
        # Transform features if needed
        if self.feature in ["drebin", "apigraph"]:
            X = self._load_or_create_vectorizer(X)
        elif self.feature in ["malscan", "mamadroid", "vae_fd"]:
            X = np.asarray(X)
            
        # Prepare train/test splits
        y = np.asarray(dataset.label)
        self.X = X
        self.X_train = X[dataset.train_idxs]
        self.y_train = y[dataset.train_idxs] 
        self.X_test = X[dataset.test_idxs]
        self.y_test = y[dataset.test_idxs]

        # Load or train classifier
        clf_path = Path(f"{self.saving_path}.clf")
        if clf_path.exists():
            logging.debug(blue(f'Loading classifier from {clf_path}...'))
            with open(clf_path, "rb") as f:
                self.clf = pickle.load(f)
        else:
            self.clf = self._initialize_classifier()
            self.clf.fit(self.X_train, self.y_train)
            logging.info(green("Training Finished! Start the next step"))

            if save:
                self.save_to_file()

    def save_to_file(self) -> None:
        """Save trained model and vectorizer to files."""
        with open(f"{self.saving_path}.clf", "wb") as f:
            pickle.dump(self.clf, f, protocol=4)

        if self.feature == "drebin":
            with open(f"{self.saving_path}.vec", "wb") as f:
                pickle.dump(self.vec, f, protocol=4)
