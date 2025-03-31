import glob
import shutil
import logging
from settings import config
import tempfile
import subprocess
import ujson as json
from utils import blue


def get_drebin_feature(apk_path, output_path=None):
    # Create a temporary directory using a context manager to ensure cleanup
    with tempfile.TemporaryDirectory(dir=config['tmp_dir']) as output_dir:
        # Define the command to run the drebin.py script
        cmd = ['python3', './drebin.py', apk_path, output_dir]

        location = config['drebin_feature_extractor']

        # Log the command execution
        logging.info(
            f"{blue('Running command')} @ '{location}': {' '.join(cmd)}")

        # Run the command
        subprocess.call(cmd, cwd=location)

        # Find the results file, which is assumed to be the only JSON in the directory
        results_file = glob.glob(f"{output_dir}/results/*.json")[0]
        logging.debug(f'Extractor results in: {results_file}')

        # Open and read the results file
        with open(results_file, 'rt') as f:
            results = json.load(f)

        # Remove the 'sha256' key from the results
        results.pop('sha256', None)

    # If an output path is provided, write the results to that file
    if output_path:
        with open(output_path, "w") as f:
            json.dump(results, f)

    # Return the results
    return results
