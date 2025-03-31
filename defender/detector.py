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


class Detector:
    def __init__(self, name, saving_path, feature, classifier):
        self.name = f"{name}.model"
        self.mlp_epochs = 1
        self.saving_path = os.path.join(
            saving_path, f"{self.name}_{self.mlp_epochs}" if classifier == "mlp" else self.name)
        self.feature = feature
        self.classifier = classifier
        self.clf = None
        self.vec = None
        self.X = self.X_train = self.y_train = self.X_test = self.y_test = None

    def build_classifier(self, dataset, save=True):
        """Build and train a classifier using the specified dataset"""
        X, X_train = self._extract_features(dataset)
        y = np.asarray(dataset.label)

        # Handle vectorization for text-based features
        if self.feature in ["drebin", "apigraph"]:
            X, X_train = self._handle_vectorizer(X, X_train)
        else:
            X = np.asarray(X)

        # Split dataset into training and testing sets
        self._split_dataset(X, y, dataset)

        # Load or train the classifier
        if os.path.exists(f"{self.saving_path}.clf"):
            self._load_model()
        else:
            self._train_classifier()

            if save:
                self.save_to_file()

    def _extract_features(self, dataset):
        """
        Extract features based on the selected feature type
        """
        X_train = None

        if self.feature == "malscan":
            X = [np.asarray(apk.malscan_feature) for apk in dataset.total_set]
        elif self.feature == "drebin":
            X = [apk.drebin_feature for apk in dataset.total_set]
            X_train = [
                dataset.total_set[train_idx].drebin_feature for train_idx in dataset.train_idxs]
        elif self.feature == "mamadroid":
            X = [np.asarray(apk.mamadroid_family_feature)
                 for apk in dataset.total_set]
        elif self.feature == "apigraph":
            X = [apk.apigraph_feature for apk in dataset.total_set]
            X_train = [
                dataset.total_set[train_idx].apigraph_feature for train_idx in dataset.train_idxs]
        elif self.feature == "vae_fd":
            X = [np.asarray(apk.vae_fd_feature) for apk in dataset.total_set]
        else:
            raise ValueError(
                f"Unknown feature extraction method: {self.feature}")

        return X, X_train

    def _handle_vectorizer(self, X, X_train):
        """Handle vectorization for text-based features"""
        vec_path = f"{self.saving_path}.vec"

        if os.path.exists(vec_path):
            logging.debug(blue(f'Loading vectorizer from {vec_path}'))
            with open(vec_path, "rb") as f:
                self.vec = pickle.load(f)
            X = self.vec.transform(X)
        else:
            self.vec = DictVectorizer()
            X_train = self.vec.fit_transform(X_train)
            X = self.vec.transform(X)

        return X, X_train

    def _split_dataset(self, X, y, dataset):
        """Split the dataset into training and testing sets"""
        train_idxs = np.asarray(dataset.train_idxs)
        test_idxs = np.asarray(dataset.test_idxs)

        self.X = X
        self.X_train = X[train_idxs]
        self.y_train = y[train_idxs]
        self.X_test = X[test_idxs]
        self.y_test = y[test_idxs]

    def _load_model(self):
        """Load a pre-trained classifier from disk"""
        model_path = f"{self.saving_path}.clf"
        logging.debug(blue(f'Loading model from {model_path}'))
        with open(model_path, "rb") as f:
            self.clf = pickle.load(f)

    def _train_classifier(self):
        """Train a new classifier"""
        classifiers = {
            "svm": LinearSVC(C=1, verbose=True),
            "3nn": KNeighborsClassifier(n_neighbors=3),
            "mlp": MLP(input_dim=self.X_train[0].shape[-1], epochs=self.mlp_epochs),
            "rf": RandomForestClassifier(max_depth=8, random_state=0),
        }

        self.clf = classifiers.get(self.classifier)
        if self.clf is None:
            raise ValueError(f"Unknown classifier type: {self.classifier}")

        self.clf.fit(self.X_train, self.y_train)
        logging.info(green("Training Finished! Start the next step"))

    def save_to_file(self):
        """Save the trained model and vectorizer to disk"""
        # Save classifier
        with open(f"{self.saving_path}.clf", "wb") as f:
            pickle.dump(self.clf, f, protocol=4)

        # Save vectorizer if needed
        if self.feature in ["drebin", "apigraph"] and self.vec is not None:
            with open(f"{self.saving_path}.vec", "wb") as f:
                pickle.dump(self.vec, f, protocol=4)
