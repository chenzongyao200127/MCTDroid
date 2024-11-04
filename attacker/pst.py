import random
import string
from itertools import combinations
from scipy.stats import norm
from settings import config
from mps.manifest import uses_feature_context, install_permissions, \
    protected_permissions, standard_activity_intent, standard_broadcast_intent, standard_category
from mps.components import load_component_candidates
from collections import deque


class ActionNode:
    def __init__(self, name, value, parent, is_leaf):
        self.name = name
        self.value = value 
        self.is_leaf = is_leaf
        self.parent = parent
        self.children = []

    def add_a_child(self, node):
        self.children.append(node)
        node.parent = self
        self.is_leaf = False

    def get_leaf_nodes_num_in_offspring(self):
        if self.is_leaf:
            return 1
        return sum([child.get_leaf_nodes_num_in_offspring() for child in self.children])

    def sample_a_path_to_leaf_node(self):
        results = []
        current_node = self
        while not current_node.is_leaf:
            results.append(current_node)
            probs = [node.value for node in current_node.children]
            current_node = random.choices(current_node.children, weights=probs)[0]
        results.append(current_node)
        return results

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
        self.android_root = ActionNode("root", None, None, True)

    def build_tree(self):
        self.generate_random_name()
        self.build_manifest_subtree()
        self.build_code_subtree()

    def build_manifest_subtree(self):
        manifest_node = ActionNode("AndroidManifest.xml", 0.5, None, True)
        self.android_root.add_a_child(manifest_node)

        uses_feature_node = self.build_uses_features_layer()
        manifest_node.add_a_child(uses_feature_node)

        permission_node = self.build_permission_layer()
        manifest_node.add_a_child(permission_node)

        intent_node = self.build_intent_layer()
        manifest_node.add_a_child(intent_node)

        self.build_middle_layer_probability(manifest_node)

    def build_code_subtree(self):
        code_node = ActionNode("code", 0.5, None, True)
        self.android_root.add_a_child(code_node)

        service_node = self.build_service_layer()
        code_node.add_a_child(service_node)
        
        receiver_node = self.build_receiver_layer()
        code_node.add_a_child(receiver_node)
        
        provider_node = self.build_provider_layer()
        code_node.add_a_child(provider_node)

        self.build_middle_layer_probability(code_node)

    def build_service_layer(self):
        service_node = ActionNode("service", None, None, True)
        services = self.sliced_components['services']
        total = len(services)
        for key, value in services.items():
            service_node.add_a_child(ActionNode((key, value), 1.0/total, None, True))
        return service_node

    def build_receiver_layer(self):
        receiver_node = ActionNode("receiver", None, None, True)
        receivers = self.sliced_components['receivers']
        total = len(receivers)
        for key, value in receivers.items():
            receiver_node.add_a_child(ActionNode((key, value), 1.0/total, None, True))
        return receiver_node

    def build_provider_layer(self):
        provider_node = ActionNode("provider", None, None, True)
        providers = self.sliced_components['providers']
        total = len(providers)
        for key, value in providers.items():
            provider_node.add_a_child(ActionNode((key, value), 1.0/total, None, True))
        return provider_node

    def generate_random_name(self):
        self.inject_activity_name = self.generate_random_activity_name()
        self.inject_receiver_name = self.generate_random_receiver_name()
        self.inject_receiver_data = ''.join(random.sample(string.ascii_letters, 8))

    def generate_random_activity_name(self):
        return ".".join(["coma", 
                        ''.join(random.sample(string.ascii_lowercase, 4)),
                        ''.join(random.sample(string.ascii_lowercase, 4)), 
                        ''.join(random.sample(string.ascii_letters, 4))])

    def generate_random_receiver_name(self):
        return ".".join(["comr",
                        ''.join(random.sample(string.ascii_lowercase, 5)),
                        ''.join(random.sample(string.ascii_lowercase, 5)),
                        ''.join(random.sample(string.ascii_letters, 5))])

    def get_normal_dis_proba(self, feature_layer):
        weights = [float(data[1]) for data in feature_layer]
        mu, std = norm.fit(weights)
        pdf = norm.pdf(weights, mu, std)
        return pdf / sum(pdf)

    def build_middle_layer_probability(self, feature_node):
        total = sum([node.get_leaf_nodes_num_in_offspring() for node in feature_node.children])
        for node in feature_node.children:
            node.value = node.get_leaf_nodes_num_in_offspring() / total

    def build_uses_features_layer(self):
        uses_feature_node = ActionNode("uses-features", None, None, True)
        hardwares = []
        softwares = []
        for feature in uses_feature_context:
            if feature not in self.apk_info["uses-features"]:
                if feature.split(".")[1] == "hardware":
                    hardwares.append(feature)
                else:
                    softwares.append(feature)

        hardware_node = self.build_hardware_layer(hardwares)
        uses_feature_node.add_a_child(hardware_node)

        software_node = self.build_software_layer(softwares)
        uses_feature_node.add_a_child(software_node)

        self.build_middle_layer_probability(uses_feature_node)

        return uses_feature_node

    def get_uses_feature_leaf_layer_list(self, wares, hard=True):
        feature_category = set()
        for feature in wares:
            key = feature.split(".")[2]
            if hard:
                if key not in feature_category:
                    flag = True
                    for exist_key in feature_category:
                        if key.startswith(exist_key):
                            flag = False
                            break
                    if flag:
                        feature_category.add(key)
            else:
                feature_category.add(key)

        key_features = {key: set() for key in feature_category}
        for feature in wares:
            for key in feature_category:
                if feature.split(".")[2].startswith(key):
                    key_features[key].add(feature)
                    break

        ware_feature_layer = [[item, len(item)] for item in key_features.values()]
        pdf_norm = self.get_normal_dis_proba(ware_feature_layer)
        for feature, proba in zip(ware_feature_layer, pdf_norm):
            feature[1] = proba
        return ware_feature_layer

    def build_hardware_layer(self, hardwares):
        hardware_node = ActionNode("hardware", None, None, True)
        hardware_feature_layer = self.get_uses_feature_leaf_layer_list(hardwares, True)
        for name, value in hardware_feature_layer:
            node = ActionNode(name, value, None, True)
            hardware_node.add_a_child(node)
            self.validation_nodes.append(("feature", node))
        return hardware_node

    def build_software_layer(self, softwares):
        software_node = ActionNode("software", None, None, True)
        software_feature_layer = self.get_uses_feature_leaf_layer_list(softwares, False)
        for name, value in software_feature_layer:
            node = ActionNode(name, value, None, True)
            software_node.add_a_child(node)
            self.validation_nodes.append(("feature", node))
        return software_node

    def get_merged_group(self, groups):
        for group1, group2 in combinations(groups, 2):
            for perm1 in group1:
                for perm2 in group2:
                    common = len(perm1[1] & perm2[1])
                    if 2 * common >= len(perm1[1]) or 2 * common >= len(perm2[1]):
                        return group1, group2
        return None

    def get_leaf_layer_list_by_cluster(self, specific_actions):
        groups = [[(action, set(action.split(".")[-1].split("_")))] for action in specific_actions]
        
        while True:
            merge_groups = self.get_merged_group(groups)
            if not merge_groups:
                break
            group1, group2 = merge_groups
            groups.remove(group1)
            groups.remove(group2)
            group1.extend(group2)
            groups.append(group1)

        leaf_layer = [[{x[0] for x in group}, len(group)] for group in groups]
        pdf_norm = self.get_normal_dis_proba(leaf_layer)
        for feature, proba in zip(leaf_layer, pdf_norm):
            feature[1] = proba
        return leaf_layer

    def build_permission_layer(self):
        permission_node = ActionNode("permission", None, None, True)
        normal_permissions = []
        signature_permissions = []
        
        for feature, scope in install_permissions:
            if self.apk_info["min_api_version"] < scope[1] and self.apk_info["max_api_version"] >= scope[0]:
                if feature not in self.apk_info["permissions"]:
                    normal_permissions.append(feature)

        for feature, scope in protected_permissions:
            if self.apk_info["min_api_version"] < scope[1] and self.apk_info["max_api_version"] >= scope[0]:
                if feature not in self.apk_info["permissions"]:
                    signature_permissions.append(feature)

        normal_permission_node = self.build_normal_permission_layer(normal_permissions)
        permission_node.add_a_child(normal_permission_node)

        signature_permission_node = self.build_signature_permission_layer(signature_permissions)
        permission_node.add_a_child(signature_permission_node)

        self.build_middle_layer_probability(permission_node)

        return permission_node

    def build_normal_permission_layer(self, normal_permissions):
        normal_permission_node = ActionNode("normal_permission", None, None, True)
        normal_permission_layer = self.get_leaf_layer_list_by_cluster(normal_permissions)
        for name, value in normal_permission_layer:
            node = ActionNode(name, value, None, True)
            normal_permission_node.add_a_child(node)
            self.validation_nodes.append(("permission", node))
        return normal_permission_node

    def build_signature_permission_layer(self, signature_permissions):
        signature_permission_node = ActionNode("signature_permission", None, None, True)
        signature_permission_layer = self.get_leaf_layer_list_by_cluster(signature_permissions)
        for name, value in signature_permission_layer:
            node = ActionNode(name, value, None, True)
            signature_permission_node.add_a_child(node)
            self.validation_nodes.append(("permission", node))
        return signature_permission_node

    def build_intent_layer(self):
        intent_node = ActionNode("intent", None, None, True)
        activity_intents = []
        broadcast_intents = []
        category_intents = []
        
        for feature, scope in standard_activity_intent:
            if self.apk_info["min_api_version"] < scope[1] and self.apk_info["max_api_version"] >= scope[0]:
                if feature not in self.apk_info["intents"]:
                    activity_intents.append(feature)

        for feature, scope in standard_broadcast_intent:
            if self.apk_info["min_api_version"] < scope[1] and self.apk_info["max_api_version"] >= scope[0]:
                if feature not in self.apk_info["intents"]:
                    broadcast_intents.append(feature)

        for feature, scope in standard_category:
            if self.apk_info["min_api_version"] < scope[1] and self.apk_info["max_api_version"] >= scope[0]:
                if feature not in self.apk_info["intents"]:
                    category_intents.append(feature)

        activity_intent_node = self.build_activity_intent_layer(activity_intents)
        intent_node.add_a_child(activity_intent_node)

        broadcast_intent_node = self.build_broadcast_intent_layer(broadcast_intents)
        intent_node.add_a_child(broadcast_intent_node)

        category_intent_node = self.build_category_intent_layer(category_intents)
        intent_node.add_a_child(category_intent_node)

        self.build_middle_layer_probability(intent_node)
        return intent_node

    def build_activity_intent_layer(self, activity_intents):
        activity_intent_node = ActionNode("activity_intent", None, None, True)
        activity_intent_layer = self.get_leaf_layer_list_by_cluster(activity_intents)
        for name, value in activity_intent_layer:
            node = ActionNode(name, value, None, True)
            activity_intent_node.add_a_child(node)
            self.validation_nodes.append(("activity_intent", node))
        return activity_intent_node

    def build_broadcast_intent_layer(self, broadcast_intents):
        broadcast_intent_node = ActionNode("broadcast_intent", None, None, True)
        broadcast_intent_layer = self.get_leaf_layer_list_by_cluster(broadcast_intents)
        for name, value in broadcast_intent_layer:
            node = ActionNode(name, value, None, True)
            broadcast_intent_node.add_a_child(node)
            self.validation_nodes.append(("broadcast_intent", node))
        return broadcast_intent_node

    def build_category_intent_layer(self, category_intents):
        category_intent_node = ActionNode("category_intent", None, None, True)
        category_intent_layer = self.get_leaf_layer_list_by_cluster(category_intents)
        for name, value in category_intent_layer:
            node = ActionNode(name, value, None, True)
            category_intent_node.add_a_child(node)
            self.validation_nodes.append(("intent_category", node))
        return category_intent_node

    def get_action(self):
        return self.android_root.sample_a_path_to_leaf_node()

    def update_code_subtree(self, action_path, results):
        node = action_path[-1]
        while True:
            parent_node = node.parent
            if parent_node is not None:
                if not node.children:
                    remain_prob = node.value
                    parent_node.children.remove(node)
                    if len(parent_node.children):
                        for child in parent_node.children:
                            if child.is_leaf:
                                child.value += remain_prob / len(parent_node.children)
                        break
                    else:
                        node = parent_node
                else:
                    raise Exception("Bugs!")

        current_node = parent_node
        if current_node.children[0].is_leaf:
            if results != 1:
                parent_node = current_node.parent
                while parent_node.name != "root":
                    self.build_middle_layer_probability(parent_node)
                    if results == 0:
                        penalty_prob = 0.1 * current_node.get_depth() * current_node.value
                        if len(parent_node.children) > 1:
                            current_node.value = current_node.value - penalty_prob
                            for node in parent_node.children:
                                if node.name != current_node.name:
                                    node.value += penalty_prob / (len(parent_node.children) - 1)
                    current_node = parent_node
                    parent_node = current_node.parent
        else:
            while current_node.name != "root":
                self.build_middle_layer_probability(current_node)
                current_node = current_node.parent

        if results == 0 or results == -1:
            root_node = action_path[0]
            manifest_node = root_node.children[0]
            code_node = root_node.children[-1]
            assert manifest_node.name == "AndroidManifest.xml" and code_node.name == "code"
            code_node.value *= 0.5
            manifest_node.value = 1.0 - code_node.value

    def update_manifest_subtree(self, action_path, results):
        node = action_path[-1]
        while True:
            parent_node = node.parent
            if parent_node is not None:
                if not node.children:
                    remain_prob = node.value
                    parent_node.children.remove(node)
                    if len(parent_node.children):
                        for child in parent_node.children:
                            if child.is_leaf:
                                child.value += remain_prob / len(parent_node.children)
                        break
                    else:
                        node = parent_node
                else:
                    raise Exception("Bugs!")

        current_node = parent_node
        if current_node.children[0].is_leaf:
            if results != 1:
                parent_node = current_node.parent
                while parent_node.name != "root":
                    self.build_middle_layer_probability(parent_node)
                    if results == 0:
                        penalty_prob = 0.1 * current_node.get_depth() * current_node.value
                        if len(parent_node.children) > 1:
                            current_node.value = current_node.value - penalty_prob
                            for node in parent_node.children:
                                if node.name != current_node.name:
                                    node.value += penalty_prob / (len(parent_node.children) - 1)
                    current_node = parent_node
                    parent_node = current_node.parent
        else:
            while current_node.name != "root":
                self.build_middle_layer_probability(current_node)
                current_node = current_node.parent

        if results == 0 or results == -1:
            root_node = action_path[0]
            manifest_node = root_node.children[0]
            code_node = root_node.children[-1]
            assert manifest_node.name == "AndroidManifest.xml" and code_node.name == "code"
            manifest_node.value *= 0.5
            code_node.value = 1.0 - manifest_node.value

    def update_tree(self, action_path, results):
        type_node = action_path[1]
        if type_node.name == "code":
            self.update_code_subtree(action_path, results)
        elif type_node.name == "AndroidManifest.xml":
            self.update_manifest_subtree(action_path, results)
        else:
            raise Exception("Not a correct node!")

    def print_tree(self, filename='PerturbationSelector.txt'):
        with open(filename, 'w') as file:
            wait_queue = deque([(self.android_root, 0)])
            prev_depth = 0

            while wait_queue:
                current_node, depth = wait_queue.popleft()
                if depth > prev_depth:
                    print(file=file)
                    print()
                prev_depth = depth

                indent = "  " * depth
                node_str = "{}Node {} : value: {}".format(indent, current_node.name, current_node.value)
                print(node_str, file=file)

                for node in current_node.children:
                    wait_queue.append((node, depth + 1))

    def get_validation_perturbation(self):
        return self.validation_nodes
