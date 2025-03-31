from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
import os
import sys
import logging
import subprocess
from settings import config
from termcolor import colored
import sklearn
import numpy as np


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
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)


def run_java_component(jar, args, cwd, timeout=None):
    """Wrapper for calling Java processes used for extraction and injection."""
    cmd = ['java', '-jar', jar, *args]
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


def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def rename_apks_to_sha256(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".apk"):
            file_path = os.path.join(directory, filename)
            # Calculate SHA256 hash of the file
            sha256 = calculate_sha256(file_path)
            new_file_path = os.path.join(directory, sha256 + ".apk")
            # Rename the file
            os.rename(file_path, new_file_path)
            print(f"Renamed {filename} to {sha256}.apk")


# # Replace 'your_directory_path' with the path to the directory containing your APK files
# directory_path = '/disk2/chenzy/MCTDroid/sample_apks/benign'
# rename_apks_to_sha256(directory_path)

# 单文件处理逻辑，返回对应的JSON数据
def process_file(filepath, label):
    file_hash = calculate_sha256(filepath)
    return {
        "sha256": file_hash,
        "name": os.path.basename(filepath),
        "label": label,
        "location": filepath  # 添加文件的绝对路径
    }


# 创建JSON数据，使用多线程
def create_json_data(folder_path, label):
    json_data = []
    with ThreadPoolExecutor() as executor:
        # 创建一个Future到文件处理函数的映射
        future_to_file = {executor.submit(process_file, os.path.join(folder_path, filename), label): filename
                          for filename in os.listdir(folder_path) if filename.endswith('.apk')}
        for future in as_completed(future_to_file):
            # 从Future中获取结果并添加到json_data列表
            json_data.append(future.result())
    return json_data


# # 文件夹路径
# benign_folder = "/disk2/Androzoo/SelectedBenign"
# malware_folder = "/disk2/Androzoo/SelectedMalware"

# # 创建JSON结构
# benign_data = create_json_data(benign_folder, 0)
# malware_data = create_json_data(malware_folder, 1)

# # 合并两部分数据
# all_data = benign_data + malware_data

# # 保存为JSON文件
# with open("apks_data.json", "w") as json_file:
#     json.dump(all_data, json_file, indent=4)

# print("JSON文件已创建。")
