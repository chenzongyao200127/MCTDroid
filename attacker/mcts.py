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
from settings import config
from androguard.misc import AnalyzeAPK
from defender.drebin import get_drebin_feature
from defender.mamadroid import get_mamadroid_feature
from attacker.pst import PerturbationSelectionTree
from utils import sign_apk
from utils import green, red, blue, magenta, cyan
from utils import run_java_component
from pprint import pprint
from datasets.apks import APK

# modification_crash_status dictionary with string keys
modification_crash_status = {'True': 0, 'False': 1, 'UnKnown': 2}

def get_basic_info(apk_path):
    results = {}
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        results["min_api_version"] = int(a.get_min_sdk_version() or 1)
        results["max_api_version"] = int(a.get_max_sdk_version() or 1000)
        results["uses-features"] = set(a.get_features())
        results["permissions"] = set(a.get_permissions())

        intent_actions = set()
        for node in a.get_android_manifest_xml().findall(".//action"):
            intent_actions.update(node.attrib.values())
        for node in a.get_android_manifest_xml().findall(".//category"):
            intent_actions.update(node.attrib.values())
        results["intents"] = intent_actions
    except Exception as e:
        apk_basename = os.path.basename(apk_path)
        logging.error(f"Error occurred in APK: {apk_basename}, Error: {e}")
        traceback.print_exc()
        return None

    return results


def execute_action(action, tmp_dir, apk_path, inject_activity_name, inject_receiver_name, inject_receiver_data):
    backup_dir = os.path.join(tmp_dir, "backup")
    process_dir = os.path.join(tmp_dir, "process")
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)

    android_manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
    if os.path.exists(android_manifest_path):
        os.remove(android_manifest_path)

    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))

    if action[1].name == "AndroidManifest.xml":
        jar = config['manifest']
        modificationType = {
            "uses-features": "feature",
            "permission": "permission",
            "activity_intent": "activity_intent",
            "broadcast_intent": "broadcast_intent"
        }.get(action[2].name, "intent_category")

        args = [
            apk_path, process_dir, config['android_sdk'], modificationType,
            ";".join(action[-1].name), inject_activity_name, inject_receiver_name,
            inject_receiver_data
        ]
    else:
        jar = config['injector']
        args = [
            apk_path, action[-1].name[0], action[2].name,
            os.path.join(config['slice_database'], f"{action[2].name}s", action[-1].name[0],
                         random.choice(action[-1].name[1])),
            process_dir, config['android_sdk']
        ]

    res = run_java_component(jar, args, tmp_dir)
    return res, backup_dir, process_dir


class SimpleAPK:
    def __init__(self, path):
        self.name = os.path.basename(path)
        self.location = path

    def print_self(self):
        print(f"APK Name: {self.name}")
        print(f"Location: {self.location}")

    def get_drebin_feature(self):
        self.drebin_feature = get_drebin_feature(self.location, self.drebin_feature_path)

    def get_mamadroid_feature(self):
        self.mamadroid_family_feature = get_mamadroid_feature(self.location, self.mamadroid_feature_path)


def predict_apk(model, location):
    if model.feature == "drebin":
        victim_feature = get_drebin_feature(location)
        victim_feature = model.vec.transform(victim_feature)
    elif model.feature == "mamadroid":
        victim_feature = np.expand_dims(get_mamadroid_feature(location), axis=0)
    else:
        raise ValueError("Unknown model feature type")

    predict_label = model.clf.predict(victim_feature)

    if model.classifier == "svm":
        predict_confidence = model.clf.decision_function(victim_feature)
    elif model.classifier in ["mlp", "rf", "3nn"]:
        predict_confidence = model.clf.predict_proba(victim_feature)[0][1]
    else:
        raise ValueError("Unknown model classifier type")

    return predict_label, predict_confidence


def colorize(text, color):
    return f"{color}{text}{color}"


class APKStateNode:
    def __init__(self, model, location, source_confidence, PerturbationSelector,
                 modification_crash=False, attack_success=False, perturbations_to_add=None):
        self.model = model
        self.apk_location = location
        self.confidence = source_confidence
        self.PerturbationSelector = PerturbationSelector
        self.modification_crash = modification_crash
        self.attack_success = attack_success
        self.perturbations_to_add = perturbations_to_add or []

        self.strategies = ['service', 'receiver', 'permission', 'intent', 'uses-features', 'provider']

    def find_children(self):
        return {self.make_moves(strategy, num_moves=3) for strategy in self.strategies}

    def find_random_child(self):
        return self.make_moves(random.choice(self.strategies), num_moves=3)

    def remove_directory(self, directory):
        try:
            shutil.rmtree(directory)
        except OSError as e:
            logging.error(f"Error removing directory {directory}: {e}")

    def reward(self):
        for action in self.perturbations_to_add:
            res, backup_dir, process_dir = execute_action(
                action,
                os.path.dirname(self.apk_location),
                self.apk_location,
                self.PerturbationSelector.inject_activity_name,
                self.PerturbationSelector.inject_receiver_name,
                self.PerturbationSelector.inject_receiver_data
            )

            curr_modification_crash = not res or 'Success' not in ''.join(res.split("\n")[-2:])

            previous_dir_basename = os.path.dirname(self.apk_location)
            process_dir_basename = os.path.basename(process_dir)
            apk_basename = os.path.basename(self.apk_location)

            logging.info(blue(f"[{previous_dir_basename}] -> [{process_dir_basename}] status: {curr_modification_crash}"))

            if curr_modification_crash:
                self.modification_crash = modification_crash_status["True"]
                self.remove_directory(backup_dir)
                self.remove_directory(process_dir)
                return -100
            else:
                self.modification_crash = modification_crash_status["False"]
                self.remove_directory(backup_dir)
                self.apk_location = os.path.join(process_dir, apk_basename)

        predict_label, next_confidence = predict_apk(self.model, self.apk_location)

        if predict_label == 0:
            logging.info(colorize(f"Attack Success ----- APK: {apk_basename}", 'green'))
            self.attack_success = True
            return 100

        confidence_diff = self.confidence - next_confidence
        self.confidence = next_confidence
        return confidence_diff

    def is_terminal(self):
        return self.modification_crash == modification_crash_status['True']

    def __str__(self):
        apk_name = os.path.basename(self.apk_location).split('.')[0]
        path_parts = self.apk_location.split('/')
        name = "root node: " + apk_name if len(path_parts) == 5 else path_parts[5]
        return f"{name} attack status: {self.attack_success}"

    def print_self(self):
        crash_status = modification_crash_status.get(str(self.modification_crash), 'UnKnown')
        perturbation_names = [x[2].name for x in self.perturbations_to_add]
        logging.info(colorize(f"len: {len(self.perturbations_to_add)}", 'red'))
        logging.info(
            f"{'=' * 100}\n"
            f"Save path: {self.apk_location}\n"
            f"confidence: {self.confidence}\n"
            f"modification_crash_status: {crash_status}\n"
            f"Perturbations To Add: {perturbation_names}\n"
            f"{'='* 100}"
        )

    def make_moves(self, strategy, num_moves=1):
        perturbations_to_add = self.get_strategy_perturbations(strategy, num_moves)
        copy_apk_path = self.backup_apk()

        logging.info(colorize(f"New APK State Location: {copy_apk_path}", 'green'))

        return APKStateNode(
            model=self.model,
            location=copy_apk_path,
            source_confidence=self.confidence,
            PerturbationSelector=self.PerturbationSelector,
            modification_crash=modification_crash_status['UnKnown'],
            attack_success=False,
            perturbations_to_add=perturbations_to_add
        )

    def get_strategy_perturbations(self, strategy, num_moves):
        perturbations_to_add = []
        for _ in range(num_moves):
            action = self.PerturbationSelector.get_action()
            while action[2].name != strategy:
                action = self.PerturbationSelector.get_action()
            perturbations_to_add.append(action)
        return perturbations_to_add

    def backup_apk(self):
        tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
        copy_apk_path = os.path.join(tmp_dir, os.path.basename(self.apk_location))
        shutil.copy(self.apk_location, copy_apk_path)
        return copy_apk_path


class MCTS:
    def __init__(self, exploration_weight=2):
        self.Q = defaultdict(int)
        self.N = defaultdict(int)
        self.children = {}
        self.exploration_weight = exploration_weight

    def find_root(self):
        for node in self.children:
            if all(node not in children for children in self.children.values()):
                return node
        return None

    def print_self(self, node=None, indent="", last=True):
        if node is None and not self.children:
            print("Empty tree")
            return
        if node is None:
            node = self.find_root()

        if self.N[node] == 0:
            print(f"{indent}{'└── ' if last else '├── '}Node {node} [Unexplored]")
        else:
            print(f"{indent}{'└── ' if last else '├── '}Node {node} [Q/N: {self.Q[node]}/{self.N[node]}]")

        indent += "    " if last else "│   "
        children = self.children.get(node, [])
        for i, child in enumerate(children):
            last_child = i == (len(children) - 1)
            self.print_self(child, indent, last_child)

    def find_attack_success_node(self, node=None):
        if node is None:
            node = self.find_root()
            if node is None:
                return None

        if node.attack_success:
            logging.info(cyan("attack success!"))
            return node

        for child in self.children.get(node, []):
            result = self.find_attack_success_node(child)
            if result is not None:
                return result

        return None

    def remove_tmp_directories(self, node=None):
        if node is None:
            node = self.find_root()

        if node is None:
            logging.error("No root node found in the tree, can't remove tmp directories or files")
            return

        project_tmp_path = os.path.abspath(os.path.join(os.curdir, 'tmp'))
        topfd = os.path.dirname(node.apk_location)
        print(f"Current node path: {topfd}")

        if not topfd.startswith(project_tmp_path):
            logging.error(f"Attempted to remove a file or directory outside of the tmp directory: {topfd}")
            return

        if os.path.isfile(topfd):
            try:
                os.remove(topfd)
                logging.info(f"Removed file: {topfd}")
            except OSError as e:
                logging.error(f"Could not remove file: {topfd}. Reason: {e.strerror}")
        elif os.path.isdir(topfd):
            try:
                shutil.rmtree(topfd)
                logging.info(f"Removed directory and all its contents: {topfd}")
            except Exception as e:
                logging.error(f"Could not remove directory: {topfd}. Reason: {e}")

        for child in self.children.get(node, []):
            self.remove_tmp_directories(child)

    def choose(self, node):
        logging.info(green("Choosing ... "))
        if node.is_terminal():
            raise RuntimeError(f"choose called on terminal node {node}")

        if node not in self.children:
            return node.find_random_child()

        def score(n):
            if self.N[n] == 0:
                return float("-inf")
            return self.Q[n] / self.N[n]

        return max(self.children[node], key=score)

    def do_rollout(self, node):
        logging.info(green("Do Rollout ... "))
        path = self._select(node)
        leaf = path[-1]
        logging.info(red(f"leaf: {leaf}"))

        self._expand(leaf)
        reward, leaf = self._simulate(leaf)
        logging.info(red(f"reward: {reward}"))

        self._backpropagate(path, reward)

    def _select(self, node):
        logging.info(green("Select"))
        path = []
        while True:
            path.append(node)
            if node not in self.children or not self.children[node]:
                return path
            unexplored = self.children[node] - set(self.children.keys())
            if unexplored:
                n = unexplored.pop()
                path.append(n)
                return path
            node = self._uct_select(node)

    def _expand(self, node):
        logging.info(green("Expand"))
        if node in self.children:
            return
        self.children[node] = node.find_children()
        logging.info(green("MTCS Tree After Expand"))

    def _simulate(self, node):
        logging.info(green("Simulate"))
        reward = node.reward()
        return reward, node

    def _backpropagate(self, path, reward):
        logging.info(green("Backpropagate"))
        for node in reversed(path):
            self.N[node] += 1
            self.Q[node] += reward

    def _uct_select(self, node):
        assert all(n in self.children for n in self.children[node])

        log_N_vertex = math.log(self.N[node])

        def uct(n):
            return self.Q[n] / self.N[n] + self.exploration_weight * math.sqrt(log_N_vertex / self.N[n])

        return max(self.children[node], key=uct)


def MCTS_attacker(apk, model, query_budget, output_result_dir):
    logging.info(cyan(f"MCTS Attack Start ----- APK: {apk.name}, Query budget: {query_budget}"))

    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk.location))
    shutil.copy(apk.location, copy_apk_path)

    back_up_apk = APK(copy_apk_path, apk.label)
    apk = back_up_apk

    source_label, source_confidence = predict_apk(model, back_up_apk.location)
    if source_label == 0:
        return

    basic_info = get_basic_info(apk.location)
    if basic_info is None:
        handle_crash("self_crash", apk, output_result_dir)
        return

    PerturbationSelector = PerturbationSelectionTree(basic_info)
    PerturbationSelector.build_tree()

    start_time = time.time()

    apk_state_root = APKStateNode(
        model,
        apk.location,
        source_confidence,
        PerturbationSelector,
        modification_crash=modification_crash_status['False'],
        attack_success=False,
        perturbations_to_add=[]
    )

    logging.info(magenta("Root APK State Node"))
    apk_state_root.print_self()

    tree = MCTS()
    choose_apk_state = apk_state_root
    success = False

    for attempt_idx in range(query_budget + 1):
        tree.do_rollout(choose_apk_state)
        choose_apk_state = tree.find_attack_success_node() or tree.choose(apk_state_root)
        if choose_apk_state and choose_apk_state.attack_success:
            log_and_copy_files("success", choose_apk_state, output_result_dir, start_time, attempt_idx)
            success = True
            break

    if not success:
        handle_failure(choose_apk_state, output_result_dir)

    tree.remove_tmp_directories()


def create_directory(path):
    os.makedirs(path, exist_ok=True)


def log_and_copy_files(status, apk_state, output_result_dir, start_time, attempt_idx):
    end_time = time.time()
    apk_name = os.path.basename(apk_state.apk_location)
    final_res_dir = os.path.join(output_result_dir, status, apk_name)
    create_directory(final_res_dir)

    logging.info(green(f"Attack {status.capitalize()} ----- APK: {apk_name}"))

    efficiency_filepath = os.path.join(final_res_dir, "efficiency.txt")
    with open(efficiency_filepath, "w") as f:
        f.write(f"{attempt_idx + 1}\n{end_time - start_time}")

    source_destination = os.path.join(final_res_dir, f"{apk_name}.source")
    adv_destination = os.path.join(final_res_dir, f"{apk_name}.adv")
    shutil.copy(apk_state.apk_location, source_destination)
    shutil.copy(apk_state.apk_location, adv_destination)


def handle_crash(crash_type, apk, output_result_dir):
    logging.info(red(f"Attack {crash_type.capitalize()} Crash ----- APK: {apk.name}"))
    final_res_dir = os.path.join(output_result_dir, crash_type, apk.name)
    create_directory(final_res_dir)


def handle_failure(apk_state, output_result_dir):
    if not apk_state:
        logging.error("No valid APK state was chosen after running MCTS.")
        return

    apk_name = os.path.basename(apk_state.apk_location)
    crash_status = apk_state.modification_crash == modification_crash_status["True"]
    status = "modification_crash" if crash_status else "fail"
    logging.info(red(f"Attack {('Modification ' if crash_status else '')}Crash ----- APK: {apk_state.apk_location}"))
    final_res_dir = os.path.join(output_result_dir, status, apk_name)
    create_directory(final_res_dir)
