import os
import logging
import pdb

from utils import blue, green
import pickle
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from lib.vae import FD_VAE_MLP
from lib.mlp import MLP
import numpy as np


class Detector:
    def __init__(self, name, saving_path, feature, classifier):
        self.name = name + ".model"
        self.mlp_epochs = 1
        self.saving_path = os.path.join(saving_path, self.name + "_" + str(
            self.mlp_epochs)) if classifier == "mlp" else os.path.join(saving_path,
                                                                       self.name)
        self.feature = feature
        self.classifier = classifier
        self.clf = None
        self.vec = None
        self.X = None
        self.X_train = None
        self.y_train = None
        self.X_test = None
        self.y_test = None

    def build_classifier(self, dataset, save=True):
        X = None
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
        elif self.feature == "fd-vae":
            X = [np.asarray(apk.vae_fd_feature) for apk in dataset.total_set]

        if X is None:
            raise Exception("Unknown Feature Extraction Method")

        y = np.asarray(dataset.label)
        if self.feature == "drebin" or self.feature == "apigraph":
            if os.path.exists(self.saving_path + ".vec"):
                logging.debug(
                    blue('Loading model from {}...'.format(self.saving_path + ".vec")))
                with open(self.saving_path + ".vec", "rb") as f:
                    self.vec = pickle.load(f)
                X = self.vec.transform(X)
            else:
                self.vec = DictVectorizer()
                X_train = self.vec.fit_transform(X_train)
                X = self.vec.transform(X)
        elif self.feature == "malscan" or self.feature == "mamadroid" or self.feature == "fd-vae":
            X = np.asarray(X)

        self.X = X
        self.X_train = X[np.asarray(dataset.train_idxs)]
        self.y_train = y[np.asarray(dataset.train_idxs)]
        self.X_test = X[np.asarray(dataset.test_idxs)]
        self.y_test = y[np.asarray(dataset.test_idxs)]

        if os.path.exists(self.saving_path + ".clf"):
            logging.debug(
                blue('Loading model from {}...'.format(self.saving_path + ".clf")))
            with open(self.saving_path + ".clf", "rb") as f:
                self.clf = pickle.load(f)
        else:
            if self.classifier == "svm":
                self.clf = LinearSVC(C=1, verbose=True)
            elif self.classifier == "3nn":
                self.clf = KNeighborsClassifier(n_neighbors=3)
            elif self.classifier == 'mlp':
                # self.clf = MLPClassifier()
                self.clf = MLP(
                    input_dim=self.X_train[0].shape[-1], epochs=self.mlp_epochs)
            elif self.classifier == "rf":
                self.clf = RandomForestClassifier(max_depth=8, random_state=0)
            elif self.classifier == "fd-vae-mlp":
                self.clf = FD_VAE_MLP()

            assert self.clf is not None

            self.clf.fit(self.X_train, self.y_train)
            logging.info(green("Training Finished! Start the next step"))

        if save and not os.path.exists(self.saving_path + ".clf"):
            self.save_to_file()

    def save_to_file(self):

        with open(self.saving_path + ".clf", "wb") as f:
            pickle.dump(self.clf, f, protocol=4)

        if self.feature == "drebin" or self.feature == "apigraph":
            with open(self.saving_path + ".vec", "wb") as f:
                pickle.dump(self.vec, f, protocol=4)
