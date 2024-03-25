import os
import json
import random
import shutil
import traceback
import multiprocessing as mp
from androguard.misc import AnalyzeAPK
from settings import config
import tempfile
from utils import run_java_component
from androguard.core.androconf import show_logging
import logging
from tqdm import tqdm


def extract_the_components_of_apk(apk_path):
    # Print the name of the APK being processed
    print("Process the APK: {}".format(os.path.basename(apk_path)))
    res_data = dict()  # Initialize an empty dictionary to store results

    try:
        # Analyze the APK file and extract its components
        a, d, dx = AnalyzeAPK(apk_path)
        # Retrieve the activities, providers, receivers, and services from the APK
        activities = a.get_activities()
        providers = a.get_providers()
        receivers = a.get_receivers()
        services = a.get_services()
        # Store these components in the res_data dictionary
        res_data["activities"] = activities
        res_data["providers"] = providers
        res_data["receivers"] = receivers
        res_data["services"] = services
        return res_data  # Return the dictionary containing the components
    except:
        # Print an error message if there's an issue processing the APK
        print("Error occurred in APK: {}".format(os.path.basename(apk_path)))
        traceback.print_exc()
        return None


def is_system_class(name):
    # Define a list of common system package prefixes
    system_packages = [
        "java.", "javax.", "android.", "androidx.", "dalvik.", "kotlin.", "kotlinx.",
        "junit.", "sun.", "org.w3c.", "org.xmlpull.", "org.xml.", "org.json.",
        "org.apache.", "com.google.", "com.android."
    ]
    for package in system_packages:
        # Check if the provided class name starts with any of the system package prefixes
        if name.startswith(package):
            return True
    return False


def slice_one_apk(apk, component_name, output_dir):
    # Retrieve necessary paths from the configuration
    apk_res_dir = config['source_apk_path']
    tmp_parent_dir = config['tmp_dir']

    # Construct the full path to the APK file by joining the resource directory and the APK filename
    apk_path = os.path.join(apk_res_dir, apk + ".apk")

    # Create a temporary directory for processing within the specified parent directory
    tmp_dir = tempfile.mkdtemp(dir=tmp_parent_dir)
    # Ensure the temporary directory exists, create it if it does not. This is redundant due to the behavior of mkdtemp.
    os.makedirs(tmp_dir, exist_ok=True)

    # Define the path where the APK will be copied for processing
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk_path))
    # Copy the APK to the newly created temporary directory for isolated processing
    shutil.copy(apk_path, copy_apk_path)

    # Retrieve the Java slicer tool executable path and the arguments from the configuration
    jar = config['slicer']
    args = [component_name, copy_apk_path, output_dir, config['android_sdk']]
    # Print the operation details to inform the user of the current process
    print("Extracting the apk - {}, Component Name - {}".format(apk, component_name))
    # Execute the Java slicer tool with the specified arguments and temporary directory as the working directory
    out = run_java_component(jar, args, tmp_dir)

    # Check if the output string contains success indication
    if "Successfully" not in out:
        # If the process was unsuccessful, create a "failed" directory in the specified output directory
        os.mkdir(os.path.join(output_dir, "failed"))

    # Remove the temporary directory and all its contents to clean up after processing
    shutil.rmtree(tmp_dir)


def get_candidate_benign_components(sampled_apk_num=100):
    # Set the logging level to INFO
    show_logging(logging.INFO)

    # Load metadata from a JSON file to sample benign apps
    with open(config['meta_data'], "r") as f:
        meta = json.load(f)

    benign_apk_paths = []
    for data in meta:
        if data['label'] == 0:
            benign_apk_paths.append(data['location'])

    # Randomly sample a specified number of APK paths
    benign_apk_paths = random.sample(benign_apk_paths, min(
        len(benign_apk_paths), sampled_apk_num))

    # Initialize sets for storing unique components
    services, providers, receivers = set(), set(), set()
    components_list = ["services", "providers", "receivers"]
    components_apk_map = {component: {}
                          for component in components_list}  # Simplified initialization

    # Process each APK to extract components
    for apk in tqdm(benign_apk_paths, desc="Extracting APK Components"):
        res_data = extract_the_components_of_apk(apk)
        for component in components_list:
            # Default to empty list if not found
            for component_class in res_data.get(component, []):
                # Assume this checks for system-specific classes
                if is_system_class(component_class):
                    continue
                # Add the component class to the appropriate set based on its type
                # Dynamically add to the correct set
                locals()[component].add(component_class)

                # Update the APK mapping for the component
                components_apk_map[component].setdefault(component_class, []).append(
                    os.path.basename(apk)[:-4])

    # Save the component-to-APK mapping to a JSON file
    with open("./slices_candidates/candidates.json", "w") as f:
        # Added indent for better readability
        json.dump(components_apk_map, f, indent=4)

    # Print summary statistics
    print(
        f"The sample num: {sampled_apk_num}, The services: {len(services)}, providers: {len(providers)}, receivers: {len(receivers)}")

    # Prepare directories for slicing and queue slicing tasks
    prepare_and_queue_slicing_tasks(components_apk_map)


def prepare_and_queue_slicing_tasks(components_apk_map):
    apk_list, component_list, output_list = [], [], []
    res_dir_path = config['slice_database']

    # Create necessary directories and queue up slicing tasks
    for component_type, components in components_apk_map.items():
        component_type_dir = os.path.join(res_dir_path, component_type)
        # Ensure the directory exists
        os.makedirs(component_type_dir, exist_ok=True)

        for component_class_name, candidate_apks in components.items():
            component_dir = os.path.join(
                component_type_dir, component_class_name)
            # Ensure the directory exists
            os.makedirs(component_dir, exist_ok=True)

            for apk in candidate_apks:
                apk_dir = os.path.join(component_dir, apk)
                # Ensure the directory exists
                os.makedirs(apk_dir, exist_ok=True)
                slice_res_dir = apk_dir  # Redundant assignment, could be used directly

                # Queue up slicing tasks
                apk_list.append(apk)
                component_list.append(component_class_name)
                output_list.append(slice_res_dir)

    # Execute slicing in parallel using multiprocessing
    with mp.Pool(processes=10) as p:
        p.starmap(slice_one_apk, zip(apk_list, component_list, output_list))


def load_component_candidates():
    # Initialize a dictionary to store components categorized as services, providers, and receivers
    sliced_components = {
        'services': dict(), 'providers': dict(), 'receivers': dict()}

    # Load the mapping of component types to APKs from a JSON file
    with open("./slices_candidates/candidates.json", "r") as f:
        component_apk_dict = json.load(f)

    # Iterate over the component-to-APK mapping to populate the sliced_components dictionary
    for component_type, value in component_apk_dict.items():
        for component_class_name, candidate_apks in value.items():
            for apk in candidate_apks:
                # Construct the directory path for the sliced result of each component
                slice_res_dir = os.path.join(
                    config['slice_database'], component_type, component_class_name, apk)
                # Check for the absence of a "failed" directory to determine successful slicing
                if not os.path.exists(os.path.join(slice_res_dir, "failed")):
                    # If the component class name does not exist in the dictionary, initialize it with the current APK
                    if sliced_components[component_type].get(component_class_name) is None:
                        sliced_components[component_type][component_class_name] = [
                            apk]
                    else:
                        # If the component class name exists, append the current APK to its list
                        sliced_components[component_type][component_class_name].append(
                            apk)

    # Return the dictionary containing categorized and successfully sliced components
    return sliced_components
