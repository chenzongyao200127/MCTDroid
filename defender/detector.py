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
        X, X_train = self._extract_features(dataset)
        y = np.asarray(dataset.label)

        if self.feature in {"drebin", "apigraph"}:
            X, X_train = self._handle_vectorizer(X, X_train)

        self._split_dataset(X, y, dataset)

        if os.path.exists(f"{self.saving_path}.clf"):
            self._load_model()
        else:
            self._train_classifier()
            if save:
                self.save_to_file()

    def _extract_features(self, dataset):
        if self.feature == "drebin":
            X = [apk.drebin_feature for apk in dataset.total_set]
            X_train = [
                dataset.total_set[train_idx].drebin_feature for train_idx in dataset.train_idxs]
        elif self.feature == "mamadroid":
            X = [np.asarray(apk.mamadroid_family_feature)
                 for apk in dataset.total_set]
            X_train = None
        else:
            raise ValueError("Unknown Feature Extraction Method")
        return X, X_train

    def _handle_vectorizer(self, X, X_train):
        if os.path.exists(f"{self.saving_path}.vec"):
            logging.debug(blue(f'Loading model from {self.saving_path}.vec'))
            with open(f"{self.saving_path}.vec", "rb") as f:
                self.vec = pickle.load(f)
            X = self.vec.transform(X)
        else:
            self.vec = DictVectorizer()
            X_train = self.vec.fit_transform(X_train)
            X = self.vec.transform(X)
        return X, X_train

    def _split_dataset(self, X, y, dataset):
        self.X = np.asarray(X)
        self.X_train = self.X[np.asarray(dataset.train_idxs)]
        self.y_train = y[np.asarray(dataset.train_idxs)]
        self.X_test = self.X[np.asarray(dataset.test_idxs)]
        self.y_test = y[np.asarray(dataset.test_idxs)]

    def _load_model(self):
        logging.debug(blue(f'Loading model from {self.saving_path}.clf'))
        with open(f"{self.saving_path}.clf", "rb") as f:
            self.clf = pickle.load(f)

    def _train_classifier(self):
        classifiers = {
            "svm": LinearSVC(C=1, verbose=True),
            "3nn": KNeighborsClassifier(n_neighbors=3),
            "mlp": MLP(input_dim=self.X_train[0].shape[-1], epochs=self.mlp_epochs),
            "rf": RandomForestClassifier(max_depth=8, random_state=0)
        }
        self.clf = classifiers.get(self.classifier)
        if self.clf is None:
            raise ValueError("Unknown Classifier Type")
        self.clf.fit(self.X_train, self.y_train)
        logging.info(green("Training Finished! Start the next step"))

    def save_to_file(self):
        with open(f"{self.saving_path}.clf", "wb") as f:
            pickle.dump(self.clf, f, protocol=4)
        if self.feature == "drebin":
            with open(f"{self.saving_path}.vec", "wb") as f:
                pickle.dump(self.vec, f, protocol=4)
