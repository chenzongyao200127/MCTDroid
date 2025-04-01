from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import hashlib
import os
import shutil
import sys
import logging
import subprocess
from settings import config
from termcolor import colored
import sklearn
import numpy as np
import multiprocessing as mp


def red(x): return colored(x, 'red')
def green(x): return colored(x, 'green')
def yellow(x): return colored(x, 'yellow')
def blue(x): return colored(x, 'blue')
def magenta(x): return colored(x, 'magenta')
def cyan(x): return colored(x, 'cyan')


def configure_logging(run_tag, debug=True):
    fmt = f'[ {run_tag} | %(asctime)s | %(name)s | %(processName)s | %(levelname)s ] %(message)s'
    datefmt = '%Y-%m-%d | %H:%M:%S'
    level = logging.DEBUG if debug else 100  # 100 == no logging

    # Create a log file with the current date and time
    log_filename = f"{run_tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file_path = os.path.join(os.getcwd(), log_filename)

    # Configure logging to both console and file
    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt=datefmt,
        handlers=[
            logging.StreamHandler(sys.stdout),  # Log to console
            logging.FileHandler(log_file_path)  # Log to file
        ]
    )


def run_java_component(jar, args, cwd, timeout=None):
    """Wrapper for calling Java processes used for extraction and injection."""
    jar_str = str(jar)
    cmd = ['java', '-jar', jar_str, *args]
    logging.info(blue('Running command') + f': {" ".join(cmd)}')

    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.PIPE, timeout=timeout, cwd=cwd)
        out = str(out, 'utf-8')
        logging.debug(blue("The output of above java command: ") + green(out))
        return out
    except subprocess.TimeoutExpired:
        logging.warning(f'Java component {jar} timed out.')
    except subprocess.CalledProcessError as e:
        exception = "\nexit code :{0} \nSTDOUT :{1} \nSTDERROR : {2} ".format(
            e.returncode,
            e.output.decode(sys.getfilesystemencoding()),
            e.stderr.decode(sys.getfilesystemencoding()))
        logging.warning(
            f'SUBPROCESS Extraction EXCEPTION: {exception}')
    return ''


def sign_apk(apk_path):
    run_java_component(config['resigner'], [
                       '--overwrite', '-a', apk_path], cwd=os.path.dirname(apk_path))


def calculate_base_metrics(model, y_pred, y_scores):
    """Calculate ROC, F1, Precision and Recall for given scores.

    Args:
        model: `Model` containing `y_test` of ground truth labels aligned with `y_pred` and `y_scores`.
        y_pred: Array of predicted labels, aligned with `y_scores` and `model.y_test`.
        y_scores: Array of predicted scores, aligned with `y_pred` and `model.y_test`.

    Returns:
        dict: Model performance stats.

    """
    if y_scores is None:
        roc = None
    else:
        if len(y_scores.shape) == 2:
            roc = sklearn.metrics.roc_auc_score(
                np.eye(2)[model.y_test], y_scores)
        else:
            roc = sklearn.metrics.roc_auc_score(model.y_test, y_scores)
    f1 = sklearn.metrics.f1_score(model.y_test, y_pred)
    precision = sklearn.metrics.precision_score(model.y_test, y_pred)
    recall = sklearn.metrics.recall_score(model.y_test, y_pred)

    return {
        'model_performance': {
            'roc': roc,
            'f1': f1,
            'precision': precision,
            'recall': recall,
        }
    }


def copy_and_rename_apks_to_sha256(source_directory, destination_directory):
    """Copy APK files from source directory to destination directory and rename them to their SHA256 hash."""
    for filename in os.listdir(source_directory):
        if filename.endswith(".apk"):
            source_file_path = os.path.join(source_directory, filename)
            # Calculate SHA256 hash of the filename only (which may contain package name)
            sha256 = calculate_sha256(filename)
            destination_file_path = os.path.join(
                destination_directory, sha256 + ".apk")
            # Copy and rename the file
            shutil.copy(source_file_path, destination_file_path)
            print(f"Copied and renamed {filename} to {sha256}.apk")


def calculate_sha256(filename):
    """Calculate SHA256 hash of a filename string."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(filename.encode('utf-8'))
    return sha256_hash.hexdigest()


def rename_and_move_apks_to_sha256(source_directory, destination_directory):
    """Rename APK files to their SHA256 hash of the original filename and move them to a new directory."""
    for filename in os.listdir(source_directory):
        if filename.endswith(".apk"):
            source_file_path = os.path.join(source_directory, filename)
            # Calculate SHA256 hash of the filename only (which may contain package name)
            sha256 = calculate_sha256(filename)
            destination_file_path = os.path.join(
                destination_directory, sha256 + ".apk")
            # Move and rename the file
            shutil.move(source_file_path, destination_file_path)

# rename_and_move_apks_to_sha256("/mnt/sdb2/andro_apk/Drebin/Benign", "/mnt/sdb2/andro_apk/Drebin/Drebin_Bengin_SHA256_APKS")

# Process a single APK file and return its metadata


def process_file(filepath, label):
    """
    Process a single APK file and return its metadata.

    Args:
        filepath: Path to the APK file
        label: Label for the APK (0 for benign, 1 for malware)

    Returns:
        dict: Metadata for the APK file
    """
    # Extract the base filename (e.g., "a3g.emyshoppinglist.apk")
    filename = os.path.basename(filepath)
    # Remove the APK extension from the filename
    filename_without_apk = filename.replace('.apk', '')
    # Calculate SHA256 hash of the filename (not the file content)
    file_hash = calculate_sha256(filename_without_apk)

    return {
        "sha256": file_hash,
        "name": filename_without_apk,
        "label": label,
        "location": filepath  # Absolute path to the file
    }


def create_json_data(folder_path, label):
    """
    Process APK files in parallel to create JSON metadata.

    Args:
        folder_path: Path to folder containing APK files
        label: Label for the APKs (0 for benign, 1 for malware)

    Returns:
        list: List of metadata dictionaries for each APK
    """
    # Find all APK files in the directory
    apk_files = [os.path.join(folder_path, filename)
                 for filename in os.listdir(folder_path)
                 if filename.endswith('.apk')]

    # Use multiprocessing with a reasonable number of workers
    num_workers = min(mp.cpu_count(), config['nproc_feature'])

    # Process files in parallel batches
    with mp.Pool(processes=num_workers) as pool:
        json_data = pool.starmap(
            process_file,
            [(filepath, label) for filepath in apk_files]
        )

    return json_data


def generate_metadata_json(benign_folder, malware_folder, output_path=None):
    """
    Generate metadata JSON file from benign and malware APK folders.

    Args:
        benign_folder: Path to folder containing benign APK files
        malware_folder: Path to folder containing malware APK files
        output_path: Path to save the JSON file (defaults to config['meta_data'])

    Returns:
        list: Combined list of metadata for all APKs
    """
    # Create JSON structures
    benign_data = create_json_data(benign_folder, 0)
    malware_data = create_json_data(malware_folder, 1)

    # Merge both datasets
    all_data = benign_data + malware_data

    # Save to JSON file
    output_file = output_path or config['meta_data']
    with open(output_file, "w") as json_file:
        json.dump(all_data, json_file, indent=4)

    return all_data

# generate_metadata_json("/mnt/sdb2/andro_apk/Drebin/Drebin_Bengin_SHA256_APKS", "/mnt/sdb2/andro_apk/Drebin/Malware")
