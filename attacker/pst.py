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
        # Initialize an ActionNode with name, value, parent node, and is_leaf status
        # Name of the node. For leaf nodes, this is the action string set; for other nodes, a particular string
        self.name = name
        # Value of the node. None for the root node; for other nodes, the choose probability
        self.value = value
        # Boolean indicating if the node is a leaf node (True) or not (False)
        self.is_leaf = is_leaf
        self.parent = parent    # Parent node of the current node. None for the root node
        self.children = []      # List to store child nodes of the current node

    def add_a_child(self, node):
        # Add a child node to the current node and update its leaf status
        self.children.append(node)  # Add the new node to the children list
        node.parent = self          # Set the current node as the parent of the new node
        # Since a new child is added, the current node cannot be a leaf node
        self.is_leaf = False

    def get_leaf_nodes_num_in_offspring(self):
        # Calculate the number of leaf nodes among the offspring of the current node
        if self.is_leaf:
            return 1  # If the current node is a leaf node, return 1
        else:
            # Recursively count leaf nodes in all children
            return sum([child_node.get_leaf_nodes_num_in_offspring() for child_node in self.children])

    def sample_a_path_to_leaf_node(self):
        # Sample a path from the current node to a leaf node based on the value probabilities of child nodes
        results = []            # Initialize a list to store the nodes in the sampled path
        current_node = self     # Start with the current node
        # Loop until a leaf node is reached
        while not current_node.is_leaf:
            results.append(current_node)    # Add the current node to the path
            # Get the choose probabilities of the children nodes
            probs = [node.value for node in current_node.children]
            # Randomly select a child node based on the probabilities and set it as the new current node
            current_node = random.choices(
                current_node.children, weights=probs)[0]
        results.append(current_node)        # Add the leaf node to the path
        return results                      # Return the sampled path

    def get_depth(self):
        # Calculate the depth of the current node in the tree
        depth = 0           # Initialize depth
        node = self.parent  # Start with the parent of the current node
        # Traverse up the tree until the root node is reached
        while node is not None:
            depth += 1      # Increment depth for each level
            node = node.parent  # Move to the parent node
        return depth        # Return the calculated depth


class PerturbationSelectionTree:
    def __init__(self, apk_info):
        self.apk_info = apk_info
        self.sliced_components = load_component_candidates()
        self.validation_nodes = []
        self.inject_activity_name = None
        self.inject_receiver_name = None
        self.inject_receiver_data = None
        self.android_root = ActionNode(
            name="root", value=None, parent=None, is_leaf=True)

    def build_tree(self):
        self.generate_random_name()

        # build init layer  ---  choose manifest or code
        self.build_manifest_subtree()
        self.build_code_subtree()

    def build_manifest_subtree(self):
        # init layer ---  manifest
        manifest_node = ActionNode(name="AndroidManifest.xml", value=0.5, parent=None,
                                   is_leaf=True)  # The value can be set adaptively
        self.android_root.add_a_child(manifest_node)

        # use-feature layer --- hardware && software
        uses_feature_node = self.build_uses_features_layer()
        manifest_node.add_a_child(uses_feature_node)

        # permission layer  --- normal permission & signature permission
        permission_node = self.build_permission_layer()
        manifest_node.add_a_child(permission_node)

        # intent layer  ---  activity intent, broadcast intent, category
        intent_node = self.build_intent_layer()
        manifest_node.add_a_child(intent_node)

        self.build_middle_layer_probability(manifest_node)

    def build_code_subtree(self):
        # init layer --- code
        # The value can be set adaptively
        code_node = ActionNode(name="code", value=0.5,
                               parent=None, is_leaf=True)
        self.android_root.add_a_child(code_node)

        # service layer
        service_node = self.build_service_layer()
        code_node.add_a_child(service_node)
        # receiver layer
        receiver_node = self.build_receiver_layer()
        code_node.add_a_child(receiver_node)
        # provider layer
        provider_node = self.build_provider_layer()
        code_node.add_a_child(provider_node)

        self.build_middle_layer_probability(code_node)

    def build_service_layer(self):
        service_node = ActionNode(
            name="service", value=None, parent=None, is_leaf=True)
        services = self.sliced_components['services']
        total_service_num = len(services)
        for key, value in services.items():
            service_component_node = ActionNode(name=(key, value), value=1.0 / total_service_num, parent=None,
                                                is_leaf=True)
            service_node.add_a_child(service_component_node)
        return service_node

    def build_receiver_layer(self):
        receiver_node = ActionNode(
            name="receiver", value=None, parent=None, is_leaf=True)
        receivers = self.sliced_components['receivers']
        total_receiver_num = len(receivers)
        for key, value in receivers.items():
            receiver_component_node = ActionNode(name=(key, value), value=1.0 / total_receiver_num, parent=None,
                                                 is_leaf=True)
            receiver_node.add_a_child(receiver_component_node)
        return receiver_node

    def build_provider_layer(self):
        provider_node = ActionNode(
            name="provider", value=None, parent=None, is_leaf=True)
        providers = self.sliced_components['providers']
        total_provider_num = len(providers)
        for key, value in providers.items():
            provider_component_node = ActionNode(name=(key, value), value=1.0 / total_provider_num, parent=None,
                                                 is_leaf=True)
            provider_node.add_a_child(provider_component_node)
        return provider_node

    def generate_random_name(self):
        self.inject_activity_name = self.generate_random_activity_name()
        self.inject_receiver_name = self.generate_random_receiver_name()
        self.inject_receiver_data = ''.join(
            random.sample(string.ascii_letters, 8))

    def generate_random_activity_name(self):
        activity_family_name = ''.join(
            random.sample(string.ascii_lowercase, 4))
        activity_package_name = ''.join(
            random.sample(string.ascii_lowercase, 4))
        activity_class_name = ''.join(random.sample(string.ascii_letters, 4))
        return ".".join(["coma", activity_family_name, activity_package_name, activity_class_name])

    def generate_random_receiver_name(self):
        receiver_family_name = ''.join(
            random.sample(string.ascii_lowercase, 5))
        receiver_package_name = ''.join(
            random.sample(string.ascii_lowercase, 5))
        receiver_class_name = ''.join(random.sample(string.ascii_letters, 5))
        return ".".join(["comr", receiver_family_name, receiver_package_name, receiver_class_name])

    def get_normal_dis_proba(self, feature_layer):
        weights = [float(data[1]) for data in feature_layer]
        mu, std = norm.fit(weights)
        pdf = norm.pdf(weights, mu, std)
        pdf_norm = pdf / sum(pdf)
        return pdf_norm

    def build_middle_layer_probability(self, feature_node):
        total_nodes = sum([node.get_leaf_nodes_num_in_offspring()
                          for node in feature_node.children])
        for node in feature_node.children:
            node.value = node.get_leaf_nodes_num_in_offspring() / total_nodes

    def build_uses_features_layer(self):
        uses_feature_node = ActionNode(
            name="uses-features", value=None, parent=None, is_leaf=True)
        hardwares = []
        softwares = []
        for feature in uses_feature_context:
            if feature.split(".")[1] == "hardware":
                if feature not in self.apk_info["uses-features"]:
                    hardwares.append(feature)
            else:
                if feature not in self.apk_info["uses-features"]:
                    softwares.append(feature)

        # build hardware feature layer
        hardware_node = self.build_hardware_layer(hardwares)
        uses_feature_node.add_a_child(hardware_node)

        # build software feature layer
        software_node = self.build_software_layer(softwares)
        uses_feature_node.add_a_child(software_node)

        # compute the hardware feature probability and software feature probability
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
        key_features = dict()
        for key in feature_category:
            key_features[key] = set()
        for feature in wares:
            for key in feature_category:
                if feature.split(".")[2].startswith(key):
                    key_features[key].add(feature)
                    break
        ware_feature_layer = []
        for key, item in key_features.items():
            ware_feature_layer.append([item, len(item)])
        pdf_norm = self.get_normal_dis_proba(ware_feature_layer)
        for feature, proba in zip(ware_feature_layer, pdf_norm):
            feature[1] = proba
        return ware_feature_layer

    def build_hardware_layer(self, hardwares):
        hardware_node = ActionNode(
            name="hardware", value=None, parent=None, is_leaf=True)
        hardware_feature_layer = self.get_uses_feature_leaf_layer_list(
            hardwares, True)
        for name, value in hardware_feature_layer:
            hardware_feature_node = ActionNode(
                name=name, value=value, parent=None, is_leaf=True)
            hardware_node.add_a_child(hardware_feature_node)
            self.validation_nodes.append(("feature", hardware_feature_node))
        return hardware_node

    def build_software_layer(self, softwares):
        software_node = ActionNode(
            name="software", value=None, parent=None, is_leaf=True)
        software_feature_layer = self.get_uses_feature_leaf_layer_list(
            softwares, False)
        for name, value in software_feature_layer:
            software_feature_node = ActionNode(
                name=name, value=value, parent=None, is_leaf=True)
            software_node.add_a_child(software_feature_node)
            self.validation_nodes.append(("feature", software_feature_node))
        return software_node

    def get_merged_group(self, groups):
        for group1, group2 in combinations(groups, 2):
            for permission_keywords1 in group1:
                for permission_keywords2 in group2:
                    common_keywords = len(
                        permission_keywords1[1] & permission_keywords2[1])
                    if 2 * common_keywords >= len(permission_keywords1[1]) or 2 * common_keywords >= len(
                            permission_keywords2[1]):
                        return group1, group2
        return None

    def get_leaf_layer_list_by_cluster(self, specific_actions):
        groups = []
        for action in specific_actions:
            groups.append([(action, set(action.split(".")[-1].split("_")))])
        while True:
            # find merge permission group
            merge_groups = self.get_merged_group(groups)

            if merge_groups is None:
                break

            # merge groups
            group1, group2 = merge_groups
            groups.remove(group1)
            groups.remove(group2)
            group1.extend(group2)
            groups.append(group1)

        leaf_layer = []
        for group in groups:
            leaf_in_group = set()
            for leaf_with_keywords in group:
                leaf_in_group.add(leaf_with_keywords[0])
            leaf_layer.append([leaf_in_group, len(leaf_in_group)])
        pdf_norm = self.get_normal_dis_proba(leaf_layer)
        for feature, proba in zip(leaf_layer, pdf_norm):
            feature[1] = proba
        return leaf_layer

    def build_permission_layer(self):
        permission_node = ActionNode(
            name="permission", value=None, parent=None, is_leaf=True)
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

        # build normal permission layer
        normal_permission_node = self.build_normal_permission_layer(
            normal_permissions)
        permission_node.add_a_child(normal_permission_node)

        # build signature permission layer
        signature_permission_node = self.build_signature_permission_layer(
            signature_permissions)
        permission_node.add_a_child(signature_permission_node)

        # compute the normal permission probability and signature permission probability
        self.build_middle_layer_probability(permission_node)

        return permission_node

    def build_normal_permission_layer(self, normal_permissions):
        normal_permission_node = ActionNode(
            name="normal_permission", value=None, parent=None, is_leaf=True)

        normal_permission_layer = self.get_leaf_layer_list_by_cluster(
            normal_permissions)

        for name, value in normal_permission_layer:
            normal_permission_feature_node = ActionNode(
                name=name, value=value, parent=None, is_leaf=True)
            normal_permission_node.add_a_child(normal_permission_feature_node)
            self.validation_nodes.append(
                ("permission", normal_permission_feature_node))
        return normal_permission_node

    def build_signature_permission_layer(self, signature_permissions):
        signature_permission_node = ActionNode(
            name="signature_permission", value=None, parent=None, is_leaf=True)

        signature_permission_layer = self.get_leaf_layer_list_by_cluster(
            signature_permissions)

        for name, value in signature_permission_layer:
            signature_permission_feature_node = ActionNode(
                name=name, value=value, parent=None, is_leaf=True)
            signature_permission_node.add_a_child(
                signature_permission_feature_node)
            self.validation_nodes.append(
                ("permission", signature_permission_feature_node))
        return signature_permission_node

    def build_intent_layer(self):
        intent_node = ActionNode(
            name="intent", value=None, parent=None, is_leaf=True)
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

        # build activity intent layer
        activity_intent_node = self.build_activity_intent_layer(
            activity_intents)
        intent_node.add_a_child(activity_intent_node)

        # build broadcast intent layer
        broadcast_intent_node = self.build_broadcast_intent_layer(
            broadcast_intents)
        intent_node.add_a_child(broadcast_intent_node)

        # build category layer
        category_intent_node = self.build_category_intent_layer(
            category_intents)
        intent_node.add_a_child(category_intent_node)

        self.build_middle_layer_probability(intent_node)
        return intent_node

    def build_activity_intent_layer(self, activity_intents):
        activity_intent_node = ActionNode(
            name="activity_intent", value=None, parent=None, is_leaf=True)

        activity_intent_layer = self.get_leaf_layer_list_by_cluster(
            activity_intents)

        for name, value in activity_intent_layer:
            activity_intent_feature_node = ActionNode(
                name=name, value=value, parent=None, is_leaf=True)
            activity_intent_node.add_a_child(activity_intent_feature_node)
            self.validation_nodes.append(
                ("activity_intent", activity_intent_feature_node))
        return activity_intent_node

    def build_broadcast_intent_layer(self, broadcast_intents):
        broadcast_intent_node = ActionNode(
            name="broadcast_intent", value=None, parent=None, is_leaf=True)

        broadcast_intent_layer = self.get_leaf_layer_list_by_cluster(
            broadcast_intents)

        for name, value in broadcast_intent_layer:
            broadcast_intent_feature_node = ActionNode(
                name=name, value=value, parent=None, is_leaf=True)
            broadcast_intent_node.add_a_child(broadcast_intent_feature_node)
            self.validation_nodes.append(
                ("broadcast_intent", broadcast_intent_feature_node))
        return broadcast_intent_node

    def build_category_intent_layer(self, category_intents):
        category_intent_node = ActionNode(
            name="category_intent", value=None, parent=None, is_leaf=True)

        category_intent_layer = self.get_leaf_layer_list_by_cluster(
            category_intents)

        for name, value in category_intent_layer:
            category_intent_feature_node = ActionNode(
                name=name, value=value, parent=None, is_leaf=True)
            category_intent_node.add_a_child(category_intent_feature_node)
            self.validation_nodes.append(
                ("intent_category", category_intent_feature_node))
        return category_intent_node

    def get_action(self):
        return self.android_root.sample_a_path_to_leaf_node()

    def update_code_subtree(self, action_path, results):
        node = action_path[-1]
        # delete node
        while True:
            parent_node = node.parent
            if parent_node is not None:
                if not node.children:
                    remain_prob = node.value
                    parent_node.children.remove(node)
                    if len(parent_node.children):
                        for child in parent_node.children:
                            if child.is_leaf:
                                child.value += remain_prob / \
                                    len(parent_node.children)
                        break
                    else:
                        node = parent_node
                else:
                    raise Exception("Bugs!")

        # adjust the weight
        current_node = parent_node
        if current_node.children[0].is_leaf:
            if results != 1:
                parent_node = current_node.parent
                while parent_node.name != "root":
                    self.build_middle_layer_probability(parent_node)
                    # add penalty
                    if results == 0:
                        penalty_prob = 0.1 * current_node.get_depth() * current_node.value
                        if len(parent_node.children) > 1:
                            current_node.value = current_node.value - penalty_prob
                            for node in parent_node.children:
                                if node.name != current_node.name:
                                    node.value += penalty_prob / \
                                        (len(parent_node.children) - 1)
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
        # delete node
        while True:
            parent_node = node.parent
            if parent_node is not None:
                if not node.children:
                    remain_prob = node.value
                    parent_node.children.remove(node)
                    if len(parent_node.children):
                        for child in parent_node.children:
                            if child.is_leaf:
                                child.value += remain_prob / \
                                    len(parent_node.children)
                        break
                    else:
                        node = parent_node
                else:
                    raise Exception("Bugs!")

        # adjust the weight
        current_node = parent_node
        if current_node.children[0].is_leaf:
            if results != 1:
                parent_node = current_node.parent
                while parent_node.name != "root":
                    self.build_middle_layer_probability(parent_node)
                    # add penalty
                    if results == 0:
                        penalty_prob = 0.1 * current_node.get_depth() * current_node.value
                        if len(parent_node.children) > 1:
                            current_node.value = current_node.value - penalty_prob
                            for node in parent_node.children:
                                if node.name != current_node.name:
                                    node.value += penalty_prob / \
                                        (len(parent_node.children) - 1)
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

                # Check if we have moved to a new level in the tree
                if depth > prev_depth:
                    print(file=file)  # Line break between levels in file
                    print()  # Line break between levels in console
                prev_depth = depth

                # Print current node with indentation based on depth
                indent = "  " * depth
                node_str = "{}Node {} : value: {}".format(
                    indent, current_node.name, current_node.value)

                print(node_str, file=file)  # Write to file
                # print(node_str)  # Print to console

                for node in current_node.children:
                    wait_queue.append((node, depth + 1))

    def get_validation_perturbation(self):
        return self.validation_nodes
