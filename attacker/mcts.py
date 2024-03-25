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
    results = dict()
    try:
        # Analyze the APK file to get basic information
        a, d, dx = AnalyzeAPK(apk_path)

        # Get the APK version
        min_api_version = a.get_min_sdk_version() or 1
        max_api_version = a.get_max_sdk_version() or 1000
        results["min_api_version"] = int(min_api_version)
        results["max_api_version"] = int(max_api_version)

        # Get the uses-features
        results["uses-features"] = set(a.get_features())

        # Get the permissions
        results["permissions"] = set(a.get_permissions())

        # Get the intent actions and categories
        intent_actions = set()
        for node in a.get_android_manifest_xml().findall(".//action"):
            intent_actions.update(node.attrib.values())
        for node in a.get_android_manifest_xml().findall(".//category"):
            intent_actions.update(node.attrib.values())
        results["intents"] = intent_actions
    except Exception as e:  # Catch all exceptions to log them and return None
        apk_basename = os.path.basename(apk_path)
        logging.error(f"Error occurred in APK: {apk_basename}, Error: {e}")
        traceback.print_exc()
        return None

    return results


def execute_action(action, tmp_dir, apk_path, inject_activity_name, inject_receiver_name, inject_receiver_data):
    # Prepare backup and processing directories within the temporary directory
    backup_dir = os.path.join(tmp_dir, "backup")
    process_dir = os.path.join(tmp_dir, "process")
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)

    # Remove the existing AndroidManifest.xml in the tmp directory if it exists
    android_manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
    if os.path.exists(android_manifest_path):
        os.remove(android_manifest_path)

    # Copy the APK to the backup directory for safekeeping
    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))

    # Determine the modification type based on the action
    if action[1].name == "AndroidManifest.xml":
        # Path to the Java tool for manifest modifications
        jar = config['manifest']
        # Identify the specific modification needed on the manifest
        if action[2].name == "uses-features":
            modificationType = "feature"
        elif action[2].name == "permission":
            modificationType = "permission"
        else:
            # Additional checks for intent-related modifications
            if action[3].name == "activity_intent":
                modificationType = "activity_intent"
            elif action[3].name == "broadcast_intent":
                modificationType = "broadcast_intent"
            else:
                modificationType = "intent_category"

        # Prepare arguments for manifest modification
        args = [
            apk_path, process_dir, config['android_sdk'], modificationType,
            ";".join(
                action[-1].name), inject_activity_name, inject_receiver_name,
            inject_receiver_data
        ]
    else:
        # Path to the Java tool for injecting components into the APK
        jar = config['injector']
        # Prepare arguments for component injection
        args = [
            apk_path, action[-1].name[0], action[2].name,
            os.path.join(
                config['slice_database'], action[2].name +
                "s", action[-1].name[0],
                random.choice(action[-1].name[1])
            ),
            process_dir, config['android_sdk']
        ]

    # Execute the Java component to apply the modification
    res = run_java_component(jar, args, tmp_dir)
    return res, backup_dir, process_dir


class simple_APK:
    def __init__(self, path):
        self.name = os.path.basename(path)
        self.location = path

    def print_self(self):
        print(f"APK Name: {self.name}")
        print(f"Location: {self.location}")

    def get_drebin_feature(self):
        self.drebin_feature = get_drebin_feature(
            self.location, self.drebin_feature_path)

    def get_mamadroid_feature(self):
        self.mamadroid_family_feature = get_mamadroid_feature(
            self.location, self.mamadroid_feature_path)


def predict_apk(model, location):
    victim_feature = None
    if model.feature == "drebin":
        victim_feature = get_drebin_feature(location)
        victim_feature = model.vec.transform(victim_feature)
    elif model.feature == "mamadroid":
        victim_feature = np.expand_dims(
            get_mamadroid_feature(location), axis=0)
    assert victim_feature is not None
    predict_label = model.clf.predict(victim_feature)

    predict_confidence = None
    if model.classifier == "svm":
        predict_confidence = model.clf.decision_function(victim_feature)
    elif model.classifier in ["mlp", "rf", "3nn"]:
        predict_confidence = model.clf.predict_proba(victim_feature)[0][1]
    assert predict_confidence is not None

    return predict_label, predict_confidence


def colorize(text, color):
    """Apply color to the given text."""
    # This function should handle the text colorization logic.
    # Replace this with the actual implementation as needed.
    return f"{color}{text}{color}"


class APKStateNode:
    def __init__(self, model, location, source_confidence, PerturbationSelector,
                 modification_crash=False, attack_success=False, perturbations_to_add=None):
        """Initialize the APKStateNode object."""
        self.model = model
        self.apk_location = location
        self.confidence = source_confidence
        self.PerturbationSelector = PerturbationSelector
        self.modification_crash = modification_crash
        self.attack_success = attack_success
        self.perturbations_to_add = perturbations_to_add if perturbations_to_add is not None else []

        self.strategies = ['service', 'receiver',
                           'permission', 'intent', 'uses-features', 'provider']

    def find_children(self):
        """Find all child nodes based on different strategies."""
        children = set()
        for strategy in self.strategies:
            node = self.make_moves(strategy, num_moves=3)
            children.add(node)
        return children

    def find_random_child(self):
        """Find a random child node based on a random strategy."""
        return self.make_moves(random.choice(self.strategies), num_moves=3)

    def remove_directory(self, directory):
        """Remove a directory safely, handling potential exceptions."""
        try:
            shutil.rmtree(directory)
        except OSError as e:
            logging.error(f"Error removing directory {directory}: {e}")

    def reward(self):
        """Calculate the reward after executing actions."""
        for action in self.perturbations_to_add:
            res, backup_dir, process_dir = execute_action(
                action,
                os.path.dirname(self.apk_location),
                self.apk_location,
                self.PerturbationSelector.inject_activity_name,
                self.PerturbationSelector.inject_receiver_name,
                self.PerturbationSelector.inject_receiver_data
            )

            curr_modification_crash = not res or 'Success' not in ''.join(
                res.split("\n")[-2:])

            previous_dir_basename = os.path.dirname(self.apk_location)
            process_dir_basename = os.path.basename(process_dir)
            apk_basename = os.path.basename(self.apk_location)

            logging.info(blue(
                f"[{previous_dir_basename}] -> [{process_dir_basename}] status: {curr_modification_crash}"))

            if curr_modification_crash:
                # Set the crash status and clean up directories safely
                self.modification_crash = modification_crash_status["True"]
                self.remove_directory(backup_dir)
                self.remove_directory(process_dir)
                return -100
            else:
                # Update the crash status, clean up the backup directory, and set the new APK location
                self.modification_crash = modification_crash_status["False"]
                self.remove_directory(backup_dir)
                self.apk_location = os.path.join(process_dir, apk_basename)

        # Predict the label and confidence for the modified APK
        predict_label, next_confidence = predict_apk(
            self.model, self.apk_location)

        if predict_label == 0:
            logging.info(
                colorize(f"Attack Success ----- APK: {apk_basename}", 'green'))
            self.attack_success = True
            return 100

        # Calculate the confidence difference and update the node's confidence
        confidence_diff = self.confidence - next_confidence
        self.confidence = next_confidence
        return confidence_diff

    def is_terminal(self):
        """Check if the current state is terminal."""
        return self.modification_crash == modification_crash_status['True']

    def __str__(self):
        """Return a string representation of the APKStateNode."""
        apk_name = os.path.basename(self.apk_location).split('.')[0]
        path_parts = self.apk_location.split('/')
        if len(path_parts) == 5:
            name = "root node: " + apk_name
        else:
            name = path_parts[5]
        return f"{name} attack status: {self.attack_success}"

    def print_self(self):
        """Print the information about the APKStateNode."""
        crash_status = modification_crash_status.get(
            str(self.modification_crash), 'UnKnown')
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
        """Create a new APKStateNode with added perturbations based on a given strategy."""
        perturbations_to_add = self.get_strategy_perturbations(
            strategy, num_moves)

        # Back up the current APK
        copy_apk_path = self.backup_apk()

        logging.info(
            colorize(f"New APK State Location: {copy_apk_path}", 'green'))

        # Create a new APKStateNode with the updated state
        new_apk_state_node = APKStateNode(
            model=self.model,
            location=copy_apk_path,
            source_confidence=self.confidence,
            PerturbationSelector=self.PerturbationSelector,
            modification_crash=modification_crash_status['UnKnown'],
            attack_success=False,
            perturbations_to_add=perturbations_to_add
        )

        return new_apk_state_node

    def get_strategy_perturbations(self, strategy, num_moves):
        """Generate perturbations to add based on the selected strategy."""
        perturbations_to_add = []
        for _ in range(num_moves):
            action = self.PerturbationSelector.get_action()
            while action[2].name != strategy:
                action = self.PerturbationSelector.get_action()
            perturbations_to_add.append(action)
        return perturbations_to_add

    def backup_apk(self):
        """Back up the current APK and return the path to the copy."""
        tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
        copy_apk_path = os.path.join(
            tmp_dir, os.path.basename(self.apk_location))
        shutil.copy(self.apk_location, copy_apk_path)
        return copy_apk_path


class MCTS:
    "Monte Carlo tree searcher. First rollout the tree then choose a move."

    def __init__(self, exploration_weight=2):
        self.Q = defaultdict(int)  # total reward of each node
        self.N = defaultdict(int)  # total visit count for each node
        self.children = dict()  # children of each node
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
            print(
                f"{indent}{'└── ' if last else '├── '}Node {node} [Unexplored]")
        else:
            print(
                f"{indent}{'└── ' if last else '├── '}Node {node} [Q/N: {self.Q[node]}/{self.N[node]}]")

        indent += "    " if last else "│   "
        children = self.children.get(node, [])
        for i, child in enumerate(children):
            last_child = i == (len(children) - 1)
            self.print_self(child, indent, last_child)

    def find_attack_success_node(self, node=None):
        """
        Traverses the tree to find a node with attack_success == True.
        Args:
            node: The starting node for traversal; if None, start from the root.
        Returns:
            The node with attack_success == True if found, otherwise None.
        """
        # Start from the root if no node is given
        if node is None:
            node = self.find_root()
            if node is None:  # If the tree is empty
                return None

        # If the node itself has attack_success == True, return it
        if node.attack_success:
            logging.info(cyan("attack success!"))
            return node

        # Otherwise, recursively check each child node
        for child in self.children.get(node, []):
            result = self.find_attack_success_node(child)
            if result is not None:  # If a child node with attack_success == True is found
                return result

        return None  # If no node with attack_success == True is found

    def remove_tmp_directories(self, node=None):
        """Recursively remove temporary directories and files in the search tree starting from the given node."""
        if node is None:
            node = self.find_root()

        if node is None:
            logging.error(
                "No root node found in the tree, can't remove tmp directories or files")
            return

        # Define the absolute path to the tmp directory within the current project
        project_tmp_path = os.path.abspath(os.path.join(os.curdir, 'tmp'))

        # This is the path to the temporary directory or file
        topfd = os.path.dirname(node.apk_location)
        print(f"Current node path: {topfd}")

        # Ensure the path is within the project's tmp directory
        if not topfd.startswith(project_tmp_path):
            logging.error(
                f"Attempted to remove a file or directory outside of the tmp directory: {topfd}")
            return

        # Check if topfd is a file and remove it if it is
        if os.path.isfile(topfd):
            try:
                os.remove(topfd)
                logging.info(f"Removed file: {topfd}")
            except OSError as e:
                logging.error(
                    f"Could not remove file: {topfd}. Reason: {e.strerror}")

        # If topfd is a directory, proceed to remove the directory and its contents
        elif os.path.isdir(topfd):
            try:
                shutil.rmtree(topfd)
                logging.info(
                    f"Removed directory and all its contents: {topfd}")
            except Exception as e:
                logging.error(
                    f"Could not remove directory: {topfd}. Reason: {e}")

        # Recursively remove temporary directories and files for all child nodes
        for child in self.children.get(node, []):
            self.remove_tmp_directories(child)

    def choose(self, node):
        """
        Choose the best successor of node (i.e., choose a move in the game).
        """
        logging.info(green("Choosing ... "))
        # If the node is terminal, there are no moves to choose from.
        if node.is_terminal():
            raise RuntimeError(f"choose called on terminal node {node}")

        # If the node has no children in the MCTS, find a random child.
        if node not in self.children:
            return node.find_random_child()

        def score(n):
            "Calculate the score of a node based on average reward."
            # Avoid selecting a node that has not been visited yet.
            if self.N[n] == 0:
                return float("-inf")

            # Calculate the average reward (total reward / visit count).
            return self.Q[n] / self.N[n]

        # Return the child with the highest score.
        return max(self.children[node], key=score)

    # MTCS kernel procedure
    def do_rollout(self, node):
        "Make the tree one layer better. (Train for one iteration.)"
        logging.info(green("Do Rollout ... "))
        # 1. SELECTION
        path = self._select(node)
        leaf = path[-1]
        logging.info(red("leaf: {}".format(leaf)))

        # 2. EXPANSION
        self._expand(leaf)

        # 3. SIMULATIONS
        reward, leaf = self._simulate(leaf)
        logging.info(red("reward: {}".format(reward)))

        # 4. BACKPROPAGATION
        self._backpropagate(path, reward)

    def _select(self, node):
        """
        Find an unexplored descendant of `node`.
        """
        logging.info(green("Select"))
        path = []
        while True:
            path.append(node)
            # Node is either unexplored or terminal.
            if node not in self.children or not self.children[node]:
                return path
            # Difference between sets gives us unexplored children.
            unexplored = self.children[node] - set(self.children.keys())
            if unexplored:
                n = unexplored.pop()
                path.append(n)
                return path
            # Use UCT to select the next node to explore.
            node = self._uct_select(node)

    def _expand(self, node):
        """
        Update the `children` dict with the children of `node`.
        """
        logging.info(green("Expand"))
        if node in self.children:
            # Already expanded.
            return
        self.children[node] = node.find_children()
        logging.info(green("MTCS Tree After Expand"))

    def _simulate(self, node):
        """
        Returns the reward for a random simulation (to completion) of `node`.
        """
        logging.info(green("Simulate"))
        reward = node.reward()

        return reward, node

    def _backpropagate(self, path, reward):
        """
        Send the reward back up to the ancestors of the leaf.
        """
        logging.info(green("Backpropagate"))
        for node in reversed(path):
            self.N[node] += 1  # Increment visit count.
            self.Q[node] += reward  # Update total reward.

    def _uct_select(self, node):
        "Select a child of node, balancing exploration & exploitation"

        # All children of node should already be expanded:
        assert all(n in self.children for n in self.children[node])

        log_N_vertex = math.log(self.N[node])

        def uct(n):
            "Upper confidence bound for trees"
            return self.Q[n] / self.N[n] + self.exploration_weight * math.sqrt(
                log_N_vertex / self.N[n]
            )

        return max(self.children[node], key=uct)


def MCTS_attacker(apk, model, query_budget, output_result_dir):
    logging.info(cyan(
        "MCTS Attack Start ----- APK: {}, Query budget: {}".format(apk.name, query_budget)))

    # Back Up Source Malware APK
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

    # construct root node
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

    # Query Budget is a Limit
    for attempt_idx in range(query_budget + 1):
        tree.do_rollout(choose_apk_state)
        choose_apk_state = tree.find_attack_success_node() or tree.choose(apk_state_root)
        if choose_apk_state and choose_apk_state.attack_success:
            log_and_copy_files("success", choose_apk_state,
                               output_result_dir, start_time, attempt_idx)
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
    logging.info(
        red(f"Attack {crash_type.capitalize()} Crash ----- APK: {apk.name}"))
    final_res_dir = os.path.join(output_result_dir, crash_type, apk.name)
    create_directory(final_res_dir)


def handle_failure(apk_state, output_result_dir):
    if not apk_state:
        logging.error("No valid APK state was chosen after running MCTS.")
        return

    apk_name = os.path.basename(apk_state.apk_location)
    crash_status = apk_state.modification_crash == modification_crash_status["True"]
    status = "modification_crash" if crash_status else "fail"
    logging.info(red(
        f"Attack {('Modification ' if crash_status else '')}Crash ----- APK: {apk_state.apk_location}"))
    final_res_dir = os.path.join(output_result_dir, status, apk_name)
    create_directory(final_res_dir)
