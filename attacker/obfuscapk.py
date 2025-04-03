# @article{aonzo2020obfuscapk,
#     title = "Obfuscapk: An open-source black-box obfuscation tool for Android apps",
#     journal = "SoftwareX",
#     volume = "11",
#     pages = "100403",
#     year = "2020",
#     issn = "2352-7110",
#     doi = "https://doi.org/10.1016/j.softx.2020.100403",
#     url = "https://www.sciencedirect.com/science/article/pii/S2352711019302791",
#     author = "Simone Aonzo and Gabriel Claudiu Georgiu and Luca Verderame and Alessio Merlo",
#     keywords = "Android, Obfuscation, Program analysis"
# }

import os
import shutil
import logging
import subprocess
import tempfile
import time
from attacker.adz import get_basic_info
from attacker.rsa import finalize_attack, get_model_predictions, get_updated_victim_feature, get_victim_feature, handle_self_crash
from utils import green, sign_apk
from utils import red, cyan
from datasets.apks import APK


def obfuscation_attack(apk, model, query_budget, output_result_dir):
    """Perform APK obfuscation attack using Obfuscapk."""
    logging.info(
        cyan(f"Attack started ----- APK: {apk.name}, Query Budget: {query_budget}"))

    # Verify Docker image installation
    try:
        subprocess.run(["docker", "run", "--rm", "-it", "obfuscapk", "--help"],
                       capture_output=True, text=True, check=True)
        logging.info("Obfuscapk Docker image test successful")
    except subprocess.CalledProcessError as e:
        logging.error(f"Obfuscapk Docker image test failed: {e.stderr}")
        return

    # Extract initial victim features
    victim_feature = get_victim_feature(apk, model)
    if victim_feature is None:
        return

    # Get initial model predictions
    source_label, source_confidence = get_model_predictions(
        model, victim_feature)
    if source_label == 0 or source_confidence is None:  # Already benign or prediction failed
        return

    # Retrieve APK basic information
    basic_info = get_basic_info(apk.location)
    if not basic_info:
        handle_self_crash(apk, output_result_dir)
        return

    # Create temporary directory and copy APK
    tmp_dir = tempfile.mkdtemp()
    copy_apk_path = os.path.join(tmp_dir, apk.name + ".apk")
    shutil.copy(apk.location, copy_apk_path)

    # Initialize attack state
    success, modification_crash, start_time = False, False, time.time()
    # Attempt obfuscation attack within query budget
    for attempt_idx in range(query_budget):
        # Define Obfuscapk obfuscation parameters
        # make sure the docker image is installed
        # ref: https://github.com/ClaudiuGeorgiu/Obfuscapk
        obfuscation_cmd = [
            "docker", "run", "--rm", "-it",
            "-v", f"/tmp:/tmp",  # Mount /tmp to access APKs
            "obfuscapk",
            "-o", "RandomManifest",  # Randomize Manifest file
            "-o", "Rebuild",         # Rebuild APK
            "-o", "NewAlignment",    # Align APK
            copy_apk_path            # Input APK file path (use copied APK)
        ]

        # Execute obfuscation
        try:
            result = subprocess.run(
                obfuscation_cmd, capture_output=True, text=True, check=True)
            logging.info(f"Obfuscation result: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Obfuscation failed: {e.stderr}")
            modification_crash = True
            break

        # Update APK path to obfuscated output
        obfuscated_apk_path = os.path.join(
            os.path.join(tmp_dir, "obfuscation_working_dir"),
            f"{apk.name.split('.')[0]}_obfuscated.apk"
        )
        if not os.path.exists(obfuscated_apk_path):
            logging.error(
                f"Obfuscated APK file not generated: {obfuscated_apk_path}")
            modification_crash = True
            break

        # Extract updated victim features
        victim_feature = get_updated_victim_feature(apk,
                                                    obfuscated_apk_path, model)
        if victim_feature is None:
            logging.error("Failed to extract features from obfuscated APK")
            modification_crash = True
            break

        # Predict label for obfuscated APK
        next_label = model.clf.predict(victim_feature)
        if next_label == 0:  # Successfully fooled the detector
            success = True
            break

    # Finalize attack and record results
    if success:
        logging.info(green("Attack Success ----- APK: {}".format(apk.name)))
    else:
        if modification_crash:
            logging.info(
                red("Attack Modification Crash ----- APK: {}".format(apk.name)))
        else:
            logging.info(red("Attack Fail ----- APK: {}".format(apk.name)))

    finalize_attack(apk, output_result_dir, success, modification_crash,
                    tmp_dir, obfuscated_apk_path if success else copy_apk_path,
                    start_time, attempt_idx)
