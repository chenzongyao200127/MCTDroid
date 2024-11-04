import json
import hashlib
import os
import sys
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

import numpy as np
import sklearn.metrics
from termcolor import colored

from settings import config

# Color formatting functions
def red(x: str) -> str: return colored(x, 'red')
def green(x: str) -> str: return colored(x, 'green') 
def yellow(x: str) -> str: return colored(x, 'yellow')
def blue(x: str) -> str: return colored(x, 'blue')
def magenta(x: str) -> str: return colored(x, 'magenta')
def cyan(x: str) -> str: return colored(x, 'cyan')

def configure_logging(run_tag: str, debug: bool = True) -> None:
    """Configure logging with consistent format."""
    fmt = f'[ {run_tag} | %(asctime)s | %(name)s | %(processName)s | %(levelname)s ] %(message)s'
    datefmt = '%Y-%m-%d | %H:%M:%S'
    level = logging.DEBUG if debug else 100  # 100 == no logging
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)

def run_java_component(jar: str, args: List[str], cwd: str, timeout: Optional[int] = None) -> str:
    """Run a Java component with error handling and logging.
    
    Args:
        jar: Path to JAR file
        args: Command line arguments
        cwd: Working directory
        timeout: Optional timeout in seconds
        
    Returns:
        Command output as string, empty string on error
    """
    cmd = ['java', '-jar', jar, *args]
    logging.info(f'{blue("Running command")}: {" ".join(cmd)}')

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE, timeout=timeout, cwd=cwd)
        out_str = out.decode('utf-8')
        logging.debug(f'{blue("Java command output: ")}{green(out_str)}')
        return out_str
    except subprocess.TimeoutExpired:
        logging.warning(f'Java component {jar} timed out')
    except subprocess.CalledProcessError as e:
        error_msg = (f'exit code: {e.returncode}\n'
                    f'stdout: {e.output.decode(sys.getfilesystemencoding())}\n'
                    f'stderr: {e.stderr.decode(sys.getfilesystemencoding())}')
        logging.warning(f'Subprocess execution failed: {error_msg}')
    return ''

def sign_apk(apk_path: str) -> None:
    """Sign an APK file using the configured resigner."""
    run_java_component(config['resigner'], 
                      ['--overwrite', '-a', apk_path],
                      cwd=os.path.dirname(apk_path))

def calculate_base_metrics(model: Any, y_pred: np.ndarray, y_scores: Optional[np.ndarray]) -> Dict[str, Dict[str, float]]:
    """Calculate model performance metrics.

    Args:
        model: Model containing y_test ground truth labels
        y_pred: Predicted labels
        y_scores: Prediction scores/probabilities

    Returns:
        Dictionary of performance metrics
    """
    roc = None
    if y_scores is not None:
        if len(y_scores.shape) == 2:
            roc = sklearn.metrics.roc_auc_score(np.eye(2)[model.y_test], y_scores)
        else:
            roc = sklearn.metrics.roc_auc_score(model.y_test, y_scores)

    metrics = {
        'model_performance': {
            'roc': roc,
            'f1': sklearn.metrics.f1_score(model.y_test, y_pred),
            'precision': sklearn.metrics.precision_score(model.y_test, y_pred),
            'recall': sklearn.metrics.recall_score(model.y_test, y_pred)
        }
    }
    return metrics

def calculate_sha256(file_path: str) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def rename_apks_to_sha256(directory: str) -> None:
    """Rename APK files to their SHA256 hash."""
    for filename in os.listdir(directory):
        if not filename.endswith('.apk'):
            continue
            
        file_path = os.path.join(directory, filename)
        sha256 = calculate_sha256(file_path)
        new_path = os.path.join(directory, f'{sha256}.apk')
        os.rename(file_path, new_path)
        logging.info(f'Renamed {filename} to {sha256}.apk')

def process_file(filepath: str, label: int) -> Dict[str, Any]:
    """Process a single APK file and return its metadata."""
    return {
        'sha256': calculate_sha256(filepath),
        'name': os.path.basename(filepath),
        'label': label,
        'location': filepath
    }

def create_json_data(folder_path: str, label: int) -> List[Dict[str, Any]]:
    """Create JSON metadata for APK files in a folder using parallel processing."""
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(process_file, os.path.join(folder_path, f), label)
            for f in os.listdir(folder_path)
            if f.endswith('.apk')
        ]
        return [f.result() for f in as_completed(futures)]
