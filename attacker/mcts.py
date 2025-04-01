from collections import defaultdict
import math
from abc import ABC, abstractmethod
import os
import shutil
import logging
import tempfile
import numpy as np
import random
import time
import traceback
from typing import Dict, Set, Tuple, Optional, List
from dataclasses import dataclass

from settings import config
from androguard.misc import AnalyzeAPK
from defender.drebin import get_drebin_feature
from defender.mamadroid import get_mamadroid_feature
from attacker.pst import PerturbationSelectionTree
from utils import sign_apk, run_java_component
from utils import green, red, blue, magenta, cyan
from datasets.apks import APK

# Constants
MODIFICATION_CRASH_STATUS = {'True': 0, 'False': 1, 'Unknown': 2}
STRATEGIES = ['service', 'receiver', 'permission',
              'intent', 'uses-features', 'provider']


@dataclass
class APKInfo:
    min_api_version: int
    max_api_version: int
    uses_features: Set[str]
    permissions: Set[str]
    intents: Set[str]


@dataclass
class APKModificationResult:
    result: Optional[str]
    backup_dir: str
    process_dir: str

# Utility Functions


def get_basic_info(apk_path: str) -> Optional[APKInfo]:
    """Extract basic information from an APK file."""
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        return APKInfo(
            min_api_version=int(a.get_min_sdk_version() or 1),
            max_api_version=int(a.get_max_sdk_version() or 1000),
            uses_features=set(a.get_features()),
            permissions=set(a.get_permissions()),
            intents=_extract_intents(a)
        )
    except Exception as e:
        logging.error(
            f"Error analyzing APK: {os.path.basename(apk_path)}, Error: {e}")
        traceback.print_exc()
        return None


def _extract_intents(apk) -> Set[str]:
    """Extract intent actions and categories from an APK's manifest."""
    intents = set()
    manifest = apk.get_android_manifest_xml()
    for node in manifest.findall(".//action"):
        intents.update(node.attrib.values())
    for node in manifest.findall(".//category"):
        intents.update(node.attrib.values())
    return intents


def execute_action(action: Tuple, tmp_dir: str, apk_path: str,
                   inject_activity_name: str, inject_receiver_name: str,
                   inject_receiver_data: str) -> APKModificationResult:
    """Execute a modification action on an APK."""
    backup_dir = os.path.join(tmp_dir, "backup")
    process_dir = os.path.join(tmp_dir, "process")
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)

    manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        os.remove(manifest_path)

    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))

    jar, args = (
        _prepare_manifest_modification(action, apk_path, process_dir,
                                       inject_activity_name, inject_receiver_name,
                                       inject_receiver_data)
        if action[1].name == "AndroidManifest.xml"
        else _prepare_component_injection(action, apk_path, process_dir)
    )

    res = run_java_component(jar, args, tmp_dir)
    return APKModificationResult(res, backup_dir, process_dir)


def _prepare_manifest_modification(action: Tuple, apk_path: str, process_dir: str,
                                   inject_activity_name: str, inject_receiver_name: str,
                                   inject_receiver_data: str) -> Tuple[str, List[str]]:
    """Prepare arguments for modifying the AndroidManifest.xml."""
    modification_type = {
        "uses-features": "feature",
        "permission": "permission",
        "activity_intent": "activity_intent",
        "broadcast_intent": "broadcast_intent"
    }.get(action[2].name, "intent_category")

    return config['manifest'], [
        apk_path, process_dir, config['android_sdk'], modification_type,
        ";".join(
            action[-1].name), inject_activity_name, inject_receiver_name, inject_receiver_data
    ]


def _prepare_component_injection(action: Tuple, apk_path: str, process_dir: str) -> Tuple[str, List[str]]:
    """Prepare arguments for injecting components into the APK."""
    return config['injector'], [
        apk_path, action[-1].name[0], action[2].name,
        os.path.join(config['slice_database'], f"{action[2].name}s",
                     action[-1].name[0], random.choice(action[-1].name[1])),
        process_dir, config['android_sdk']
    ]


def predict_apk(model, location: str) -> Tuple[int, float]:
    """Predict the label and confidence of an APK using the given model."""
    if model.feature == "drebin":
        victim_feature = model.vec.transform(get_drebin_feature(location))
    elif model.feature == "mamadroid":
        victim_feature = np.expand_dims(
            get_mamadroid_feature(location), axis=0)
    # TODO: Add support for other feature types
    else:
        raise ValueError(f"Unsupported model feature type: {model.feature}")

    predict_label = model.clf.predict(victim_feature)
    predict_confidence = (
        model.clf.decision_function(victim_feature)
        if model.classifier == "svm"
        else model.clf.predict_proba(victim_feature)[0][1]
    )
    return predict_label[0], predict_confidence


class APKStateNode:
    def __init__(self, model, location: str, confidence: float,
                 perturbation_selector: PerturbationSelectionTree,
                 modification_crash: int = MODIFICATION_CRASH_STATUS['Unknown'],
                 attack_success: bool = False, perturbations: List[Tuple] = None):
        self.model = model
        self.apk_location = location
        self.confidence = confidence
        self.perturbation_selector = perturbation_selector
        self.modification_crash = modification_crash
        self.attack_success = attack_success
        self.perturbations = perturbations or []

    def find_random_child(self) -> 'APKStateNode':
        """Create a random child node."""
        return self.make_moves(random.choice(STRATEGIES), num_moves=3)

    def reward(self) -> float:
        """Calculate the reward for the current state."""
        for action in self.perturbations:
            res, backup_dir, process_dir = execute_action(
                action, os.path.dirname(self.apk_location), self.apk_location,
                self.perturbation_selector.inject_activity_name,
                self.perturbation_selector.inject_receiver_name,
                self.perturbation_selector.inject_receiver_data
            )

            curr_modification_crash = not res or 'Success' not in ''.join(
                res.splitlines()[-2:])
            logging.info(blue(f"[{os.path.dirname(self.apk_location)}] -> [{os.path.basename(process_dir)}] "
                              f"status: {curr_modification_crash}"))

            if curr_modification_crash:
                self.modification_crash = MODIFICATION_CRASH_STATUS["True"]
                shutil.rmtree(backup_dir, ignore_errors=True)
                shutil.rmtree(process_dir, ignore_errors=True)
                return -100.0

            self.modification_crash = MODIFICATION_CRASH_STATUS["False"]
            shutil.rmtree(backup_dir, ignore_errors=True)
            self.apk_location = os.path.join(
                process_dir, os.path.basename(self.apk_location))

        predict_label, next_confidence = predict_apk(
            self.model, self.apk_location)
        if predict_label == 0:
            logging.info(
                green(f"Attack Success ----- APK: {os.path.basename(self.apk_location)}"))
            self.attack_success = True
            return 100.0

        confidence_diff = self.confidence - next_confidence
        self.confidence = next_confidence
        return confidence_diff

    def is_terminal(self) -> bool:
        """Check if the node is terminal."""
        return self.modification_crash == MODIFICATION_CRASH_STATUS['True']

    def make_moves(self, strategy: str, num_moves: int = 1) -> 'APKStateNode':
        """Generate a new state by applying perturbations."""
        perturbations = []
        for _ in range(num_moves):
            action = self.perturbation_selector.get_action()
            while action[2].name != strategy:
                action = self.perturbation_selector.get_action()
            perturbations.append(action)

        copy_apk_path = self._backup_apk()
        logging.info(green(f"New APK State Location: {copy_apk_path}"))

        return APKStateNode(
            model=self.model, location=copy_apk_path, confidence=self.confidence,
            perturbation_selector=self.perturbation_selector,
            modification_crash=MODIFICATION_CRASH_STATUS['Unknown'],
            attack_success=False, perturbations=perturbations
        )

    def _backup_apk(self) -> str:
        """Backup the APK to a temporary location."""
        tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
        copy_apk_path = os.path.join(
            tmp_dir, os.path.basename(self.apk_location))
        shutil.copy(self.apk_location, copy_apk_path)
        return copy_apk_path


class MCTS:
    def __init__(self, exploration_weight: float = 2.0):
        self.Q = defaultdict(float)  # Total reward of each node
        self.N = defaultdict(int)    # Total visit count for each node
        self.children = {}           # Children of each node
        self.exploration_weight = exploration_weight

    def do_rollout(self, node: APKStateNode) -> None:
        """Perform one iteration of MCTS."""
        logging.info(green("Performing rollout..."))
        path = self._select(node)
        leaf = path[-1]
        self._expand(leaf)
        reward = self._simulate(leaf)
        self._backpropagate(path, reward)

    def _select(self, node: APKStateNode) -> List[APKStateNode]:
        """Select a path to an unexplored node."""
        path = []
        while True:
            path.append(node)
            if node not in self.children or not self.children[node]:
                return path
            unexplored = self.children[node] - set(self.children.keys())
            if unexplored:
                path.append(unexplored.pop())
                return path
            node = self._uct_select(node)

    def _expand(self, node: APKStateNode) -> None:
        """Expand the tree by adding children of the node."""
        if node not in self.children:
            self.children[node] = {self.make_moves(
                strategy, num_moves=3) for strategy in STRATEGIES}

    def _simulate(self, node: APKStateNode) -> float:
        """Simulate a random rollout and return the reward."""
        return node.reward()

    def _backpropagate(self, path: List[APKStateNode], reward: float) -> None:
        """Propagate the reward back up the tree."""
        for node in reversed(path):
            self.N[node] += 1
            self.Q[node] += reward

    def _uct_select(self, node: APKStateNode) -> APKStateNode:
        """Select a child node using the UCT formula."""
        log_N_vertex = math.log(self.N[node])
        return max(self.children[node], key=lambda n:
                   self.Q[n] / self.N[n] + self.exploration_weight * math.sqrt(log_N_vertex / self.N[n]))

    def choose(self, node: APKStateNode) -> APKStateNode:
        """Choose the best successor of a node."""
        if node.is_terminal():
            raise RuntimeError(f"Cannot choose from terminal node {node}")
        if node not in self.children:
            return node.find_random_child()
        return max(self.children[node], key=lambda n: self.Q[n] / self.N[n] if self.N[n] else float("-inf"))


def MCTS_attacker(apk: APK, model, query_budget: int, output_result_dir: str) -> None:
    """Perform an MCTS-based attack on an APK."""
    logging.info(
        cyan(f"Starting MCTS attack on APK: {apk.name}, Query budget: {query_budget}"))

    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk.location))
    shutil.copy(apk.location, copy_apk_path)

    apk = APK(copy_apk_path, apk.label)
    source_label, source_confidence = predict_apk(model, apk.location)
    if source_label == 0:
        return

    basic_info = get_basic_info(apk.location)
    if basic_info is None:
        handle_crash("self_crash", apk, output_result_dir)
        return

    perturbation_selector = PerturbationSelectionTree(basic_info)
    perturbation_selector.build_tree()

    start_time = time.time()
    root_node = APKStateNode(
        model, apk.location, source_confidence, perturbation_selector,
        modification_crash=MODIFICATION_CRASH_STATUS['False']
    )

    tree = MCTS()
    current_node = root_node

    for attempt_idx in range(query_budget + 1):
        tree.do_rollout(current_node)
        current_node = tree.choose(root_node)
        if current_node.attack_success:
            log_and_copy_files("success", current_node,
                               output_result_dir, start_time, attempt_idx)
            break
    else:
        handle_failure(current_node, output_result_dir)

    tree.remove_tmp_directories()


def log_and_copy_files(status: str, apk_state: APKStateNode, output_result_dir: str,
                       start_time: float, attempt_idx: int) -> None:
    """Log attack results and copy files to the output directory."""
    end_time = time.time()
    apk_name = os.path.basename(apk_state.apk_location)
    result_dir = os.path.join(output_result_dir, status, apk_name)
    os.makedirs(result_dir, exist_ok=True)

    logging.info(green(f"Attack {status.capitalize()} on APK: {apk_name}"))
    with open(os.path.join(result_dir, "efficiency.txt"), "w") as f:
        f.write(f"{attempt_idx + 1}\n{end_time - start_time}")

    shutil.copy(apk_state.apk_location, os.path.join(
        result_dir, f"{apk_name}.source"))
    shutil.copy(apk_state.apk_location, os.path.join(
        result_dir, f"{apk_name}.adv"))


def handle_crash(crash_type: str, apk: APK, output_result_dir: str) -> None:
    """Handle crashes during the attack."""
    logging.info(
        red(f"Attack {crash_type.capitalize()} Crash on APK: {apk.name}"))
    os.makedirs(os.path.join(output_result_dir,
                crash_type, apk.name), exist_ok=True)


def handle_failure(apk_state: APKStateNode, output_result_dir: str) -> None:
    """Handle failure cases during the attack."""
    if not apk_state:
        logging.error("No valid APK state was chosen after running MCTS.")
        return

    apk_name = os.path.basename(apk_state.apk_location)
    status = "modification_crash" if apk_state.modification_crash == MODIFICATION_CRASH_STATUS[
        "True"] else "fail"
    logging.info(red(f"Attack {status.capitalize()} on APK: {apk_name}"))
    os.makedirs(os.path.join(output_result_dir,
                status, apk_name), exist_ok=True)
