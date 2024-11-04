import glob
import shutil
import logging
from settings import config
import tempfile
import subprocess
import ujson as json
from utils import blue


def get_drebin_feature(apk_path, output_path=None):
    with tempfile.TemporaryDirectory(dir=config['tmp_dir']) as output_dir:
        cmd = ['python3', './drebin.py', apk_path, output_dir]
        location = config['drebin_feature_extractor']

        logging.info(f"{blue('Running command')} @ '{location}': {' '.join(cmd)}")
        subprocess.call(cmd, cwd=location)

        results_file = glob.glob(f"{output_dir}/results/*.json")[0]
        logging.debug(f'Extractor results in: {results_file}')

        with open(results_file, 'rt') as f:
            results = json.load(f)

        results.pop('sha256', None)

    if output_path is not None:
        with open(output_path, "w") as f:
            json.dump(results, f)

    return results
