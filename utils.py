import json
import hashlib
import os
import sys
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from functools import lru_cache
from pathlib import Path

import numpy as np
import sklearn.metrics
from termcolor import colored

from settings import config

# Color formatting using dict for better performance
COLORS = {
    'red': lambda x: colored(x, 'red'),
    'green': lambda x: colored(x, 'green'),
    'yellow': lambda x: colored(x, 'yellow'), 
    'blue': lambda x: colored(x, 'blue'),
    'magenta': lambda x: colored(x, 'magenta'),
    'cyan': lambda x: colored(x, 'cyan')
}

# Use functions from dict for better performance
red = COLORS['red']
green = COLORS['green']
yellow = COLORS['yellow']
blue = COLORS['blue']
magenta = COLORS['magenta'] 
cyan = COLORS['cyan']

def configure_logging(run_tag: str, debug: bool = True) -> None:
    """Configure logging with consistent format."""
    fmt = f'[ {run_tag} | %(asctime)s | %(name)s | %(processName)s | %(levelname)s ] %(message)s'
    datefmt = '%Y-%m-%d | %H:%M:%S'
    level = logging.DEBUG if debug else 100
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)

def run_java_component(jar: str, args: List[str], cwd: str, timeout: Optional[int] = None) -> str:
    """Run a Java component with error handling and logging."""
    cmd = ['java', '-jar', jar, *args]
    logging.info(f'{blue("Running command")}: {" ".join(cmd)}')
    logging.info(f'{blue("Running command")}: {" ".join(cmd)}')

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd, text=True, check=True)
        logging.debug(f'{blue("Java command output: ")}{green(proc.stdout)}')
        return proc.stdout
    except subprocess.TimeoutExpired:
        logging.warning(f'Java component {jar} timed out')
        logging.warning(f'Java component {jar} timed out')
    except subprocess.CalledProcessError as e:
        error_msg = (f'exit code: {e.returncode}\n'
                    f'stdout: {e.stdout}\n'
                    f'stderr: {e.stderr}')
        logging.warning(f'Subprocess execution failed: {error_msg}')
    return ''

def sign_apk(apk_path: str) -> None:
    """Sign an APK file using the configured resigner."""
    run_java_component(config['resigner'],
                      ['--overwrite', '-a', apk_path],
                      cwd=Path(apk_path).parent)

def calculate_base_metrics(model: Any, y_pred: np.ndarray, y_scores: Optional[np.ndarray]) -> Dict[str, Dict[str, float]]:
    """Calculate model performance metrics."""
    roc = None
    if y_scores is not None:
        if len(y_scores.shape) == 2:
            roc = sklearn.metrics.roc_auc_score(np.eye(2)[model.y_test], y_scores)
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

@lru_cache(maxsize=1024)
def calculate_sha256(file_path: str) -> str:
    """Calculate SHA256 hash of a file with caching."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def rename_apks_to_sha256(directory: str) -> None:
    """Rename APK files to their SHA256 hash."""
    for path in Path(directory).glob('*.apk'):
        sha256 = calculate_sha256(str(path))
        new_path = path.parent / f'{sha256}.apk'
        path.rename(new_path)
        logging.info(f'Renamed {path.name} to {sha256}.apk')

def process_file(filepath: str, label: int) -> Dict[str, Any]:
    """Process a single APK file and return its metadata."""
    path = Path(filepath)
    return {
        'sha256': calculate_sha256(str(path)),
        'name': path.name,
        'label': label,
        'location': str(path)
    }

def create_json_data(folder_path: str, label: int) -> List[Dict[str, Any]]:
    """Create JSON metadata for APK files in a folder using parallel processing."""
    apk_files = list(Path(folder_path).glob('*.apk'))
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(process_file, str(f), label)
            for f in apk_files
        ]
        return [f.result() for f in as_completed(futures)]
