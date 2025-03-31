import random
import string
from itertools import combinations
from scipy.stats import norm
from settings import config
from mps.manifest import (
    uses_feature_context, install_permissions, protected_permissions,
    standard_activity_intent, standard_broadcast_intent, standard_category
)
from mps.components import load_component_candidates
from collections import deque


class ActionNode:
    def __init__(self, name, value=None, parent=None, is_leaf=True):
        self.name = name
        self.value = value
        self.is_leaf = is_leaf
        self.parent = parent
        self.children = []

    def add_child(self, node):
        self.children.append(node)
        node.parent = self
        self.is_leaf = False

    def count_leaf_nodes(self):
        return 1 if self.is_leaf else sum(child.count_leaf_nodes() for child in self.children)

    def sample_path_to_leaf(self):
        path = []
        current_node = self
        while not current_node.is_leaf:
            path.append(current_node)
            current_node = random.choices(current_node.children, weights=[
                                          child.value for child in current_node.children])[0]
        path.append(current_node)
        return path

    def get_depth(self):
        depth = 0
        node = self.parent
        while node:
            depth += 1
            node = node.parent
        return depth


class PerturbationSelectionTree:
    def __init__(self, apk_info):
        self.apk_info = apk_info
        self.sliced_components = load_component_candidates()
        self.validation_nodes = []
        self.inject_activity_name = None
        self.inject_receiver_name = None
        self.inject_receiver_data = None
        self.android_root = ActionNode(name="root")

    def build_tree(self):
        self.generate_random_names()
        self.build_manifest_subtree()
        self.build_code_subtree()

    def build_manifest_subtree(self):
        manifest_node = ActionNode(name="AndroidManifest.xml", value=0.5)
        self.android_root.add_child(manifest_node)

        manifest_node.add_child(self.build_uses_features_layer())
        manifest_node.add_child(self.build_permission_layer())
        manifest_node.add_child(self.build_intent_layer())

        self.update_layer_probabilities(manifest_node)

    def build_code_subtree(self):
        code_node = ActionNode(name="code", value=0.5)
        self.android_root.add_child(code_node)

        code_node.add_child(self.build_service_layer())
        code_node.add_child(self.build_receiver_layer())
        code_node.add_child(self.build_provider_layer())

        self.update_layer_probabilities(code_node)

    def build_service_layer(self):
        return self.build_component_layer("service", self.sliced_components['services'])

    def build_receiver_layer(self):
        return self.build_component_layer("receiver", self.sliced_components['receivers'])

    def build_provider_layer(self):
        return self.build_component_layer("provider", self.sliced_components['providers'])

    def build_component_layer(self, name, components):
        node = ActionNode(name=name)
        total = len(components)
        for key, value in components.items():
            node.add_child(ActionNode(name=(key, value), value=1.0 / total))
        return node

    def generate_random_names(self):
        self.inject_activity_name = self.generate_random_name("coma")
        self.inject_receiver_name = self.generate_random_name("comr")
        self.inject_receiver_data = ''.join(
            random.choices(string.ascii_letters, k=8))

    def generate_random_name(self, prefix):
        return ".".join([
            prefix,
            ''.join(random.choices(string.ascii_lowercase, k=4)),
            ''.join(random.choices(string.ascii_lowercase, k=4)),
            ''.join(random.choices(string.ascii_letters, k=4))
        ])

    def update_layer_probabilities(self, node):
        total_leaves = sum(child.count_leaf_nodes() for child in node.children)
        for child in node.children:
            child.value = child.count_leaf_nodes() / total_leaves

    def build_uses_features_layer(self):
        uses_feature_node = ActionNode(name="uses-features")
        hardwares, softwares = self.split_features(uses_feature_context)

        uses_feature_node.add_child(
            self.build_feature_layer("hardware", hardwares, True))
        uses_feature_node.add_child(
            self.build_feature_layer("software", softwares, False))

        self.update_layer_probabilities(uses_feature_node)
        return uses_feature_node

    def split_features(self, features):
        hardwares, softwares = [], []
        for feature in features:
            if feature.split(".")[1] == "hardware":
                if feature not in self.apk_info["uses-features"]:
                    hardwares.append(feature)
            else:
                if feature not in self.apk_info["uses-features"]:
                    softwares.append(feature)
        return hardwares, softwares

    def build_feature_layer(self, name, features, is_hardware):
        node = ActionNode(name=name)
        feature_layer = self.get_feature_leaf_layer(features, is_hardware)
        for feature_set, prob in feature_layer:
            feature_node = ActionNode(name=feature_set, value=prob)
            node.add_child(feature_node)
            self.validation_nodes.append(("feature", feature_node))
        return node

    def get_feature_leaf_layer(self, features, is_hardware):
        categories = self.categorize_features(features, is_hardware)
        feature_layer = [[features, len(features)]
                         for features in categories.values()]
        probabilities = self.calculate_normalized_probabilities(feature_layer)
        for feature, prob in zip(feature_layer, probabilities):
            feature[1] = prob
        return feature_layer

    def categorize_features(self, features, is_hardware):
        categories = {}
        for feature in features:
            key = feature.split(".")[2]
            if is_hardware:
                if not any(key.startswith(existing) for existing in categories):
                    categories[key] = set()
            else:
                categories.setdefault(key, set())
            categories[key].add(feature)
        return categories

    def calculate_normalized_probabilities(self, feature_layer):
        weights = [float(data[1]) for data in feature_layer]
        mu, std = norm.fit(weights)
        pdf = norm.pdf(weights, mu, std)
        return pdf / sum(pdf)

    def build_permission_layer(self):
        permission_node = ActionNode(name="permission")
        normal_permissions, signature_permissions = self.split_permissions()

        permission_node.add_child(self.build_permission_sub_layer(
            "normal_permission", normal_permissions))
        permission_node.add_child(self.build_permission_sub_layer(
            "signature_permission", signature_permissions))

        self.update_layer_probabilities(permission_node)
        return permission_node

    def split_permissions(self):
        normal_permissions, signature_permissions = [], []
        for feature, scope in install_permissions:
            if self.is_within_api_scope(scope) and feature not in self.apk_info["permissions"]:
                normal_permissions.append(feature)
        for feature, scope in protected_permissions:
            if self.is_within_api_scope(scope) and feature not in self.apk_info["permissions"]:
                signature_permissions.append(feature)
        return normal_permissions, signature_permissions

    def is_within_api_scope(self, scope):
        return self.apk_info["min_api_version"] < scope[1] and self.apk_info["max_api_version"] >= scope[0]

    def build_permission_sub_layer(self, name, permissions):
        node = ActionNode(name=name)
        permission_layer = self.get_leaf_layer_by_cluster(permissions)
        for permission_set, prob in permission_layer:
            permission_node = ActionNode(name=permission_set, value=prob)
            node.add_child(permission_node)
            self.validation_nodes.append(("permission", permission_node))
        return node

    def get_leaf_layer_by_cluster(self, actions):
        groups = [[(action, set(action.split(".")[-1].split("_")))]
                  for action in actions]
        while True:
            merged_groups = self.merge_groups(groups)
            if not merged_groups:
                break
            group1, group2 = merged_groups
            groups.remove(group1)
            groups.remove(group2)
            groups.append(group1 + group2)

        leaf_layer = [[{leaf[0]
                        for leaf in group}, len(group)] for group in groups]
        probabilities = self.calculate_normalized_probabilities(leaf_layer)
        for feature, prob in zip(leaf_layer, probabilities):
            feature[1] = prob
        return leaf_layer

    def merge_groups(self, groups):
        for group1, group2 in combinations(groups, 2):
            if self.should_merge_groups(group1, group2):
                return group1, group2
        return None

    def should_merge_groups(self, group1, group2):
        for perm1 in group1:
            for perm2 in group2:
                common = len(perm1[1] & perm2[1])
                if 2 * common >= len(perm1[1]) or 2 * common >= len(perm2[1]):
                    return True
        return False

    def build_intent_layer(self):
        intent_node = ActionNode(name="intent")
        activity_intents, broadcast_intents, category_intents = self.split_intents()

        intent_node.add_child(self.build_intent_sub_layer(
            "activity_intent", activity_intents))
        intent_node.add_child(self.build_intent_sub_layer(
            "broadcast_intent", broadcast_intents))
        intent_node.add_child(self.build_intent_sub_layer(
            "category_intent", category_intents))

        self.update_layer_probabilities(intent_node)
        return intent_node

    def split_intents(self):
        activity_intents, broadcast_intents, category_intents = [], [], []
        for feature, scope in standard_activity_intent:
            if self.is_within_api_scope(scope) and feature not in self.apk_info["intents"]:
                activity_intents.append(feature)
        for feature, scope in standard_broadcast_intent:
            if self.is_within_api_scope(scope) and feature not in self.apk_info["intents"]:
                broadcast_intents.append(feature)
        for feature, scope in standard_category:
            if self.is_within_api_scope(scope) and feature not in self.apk_info["intents"]:
                category_intents.append(feature)
        return activity_intents, broadcast_intents, category_intents

    def build_intent_sub_layer(self, name, intents):
        node = ActionNode(name=name)
        intent_layer = self.get_leaf_layer_by_cluster(intents)
        for intent_set, prob in intent_layer:
            intent_node = ActionNode(name=intent_set, value=prob)
            node.add_child(intent_node)
            self.validation_nodes.append((name, intent_node))
        return node

    def get_action(self):
        return self.android_root.sample_path_to_leaf()

    def update_tree(self, action_path, results):
        type_node = action_path[1]
        if type_node.name == "code":
            self.update_subtree(action_path, results, is_code=True)
        elif type_node.name == "AndroidManifest.xml":
            self.update_subtree(action_path, results, is_code=False)
        else:
            raise ValueError("Invalid node type!")

    def update_subtree(self, action_path, results, is_code):
        node = action_path[-1]
        while node.parent:
            parent = node.parent
            if not node.children:
                remain_prob = node.value
                parent.children.remove(node)
                if parent.children:
                    for child in parent.children:
                        if child.is_leaf:
                            child.value += remain_prob / len(parent.children)
                    break
                else:
                    node = parent
            else:
                raise RuntimeError("Unexpected tree structure!")

        current_node = parent
        if current_node.children[0].is_leaf:
            if results != 1:
                self.apply_penalty(current_node, results)
        else:
            while current_node.name != "root":
                self.update_layer_probabilities(current_node)
                current_node = current_node.parent

        if results in {0, -1}:
            root_node = action_path[0]
            manifest_node, code_node = root_node.children
            if is_code:
                code_node.value *= 0.5
                manifest_node.value = 1.0 - code_node.value
            else:
                manifest_node.value *= 0.5
                code_node.value = 1.0 - manifest_node.value

    def apply_penalty(self, node, results):
        parent = node.parent
        while parent.name != "root":
            self.update_layer_probabilities(parent)
            if results == 0:
                penalty = 0.1 * node.get_depth() * node.value
                if len(parent.children) > 1:
                    node.value -= penalty
                    for sibling in parent.children:
                        if sibling.name != node.name:
                            sibling.value += penalty / \
                                (len(parent.children) - 1)
            node = parent
            parent = node.parent

    def print_tree(self, filename='PerturbationSelector.txt'):
        with open(filename, 'w') as file:
            queue = deque([(self.android_root, 0)])
            prev_depth = 0

            while queue:
                current_node, depth = queue.popleft()
                if depth > prev_depth:
                    print(file=file)
                prev_depth = depth

                indent = "  " * depth
                print(
                    f"{indent}Node {current_node.name} : value: {current_node.value}", file=file)

                for child in current_node.children:
                    queue.append((child, depth + 1))

    def get_validation_perturbation(self):
        return self.validation_nodes
