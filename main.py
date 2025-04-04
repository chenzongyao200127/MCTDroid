import random
import argparse
import os
from attacker.obfuscapk import obfuscation_attack
import utils
import shutil
import logging
import numpy as np
import multiprocessing as mp

from settings import config
from utils import blue, green, calculate_base_metrics
from pprint import pformat
from itertools import repeat
from datasets.apks import APKSET
from defender.detector import Detector
from mps.components import get_candidate_benign_components
from attacker.mcts import MCTS_attacker
from attacker.adz import AdvDroidZero_attacker
from attacker.rsa import random_select_attacker
from androguard.core.androconf import show_logging
from datetime import datetime

random.seed(42)


def main():
    args = parse_args()
    utils.configure_logging(args.run_tag, args.debug)

    output_result_dir = prepare_res_save_dir(args)

    # STAGE - Building the Malware Detection Methods
    logging.info(
        blue('Begin Stage ------- Building the Malware Detection Methods'))

    dataset = initialize_dataset(args)
    if config['extract_feature']:
        exit()

    model = build_and_test_model(args, dataset)
    if args.train_model:
        exit()

    tp_apks = prepare_tp_apks(args, dataset, model)

    # STAGE - Creating the Malware Perturbation Set
    if args.create_mps:
        get_candidate_benign_components()
        exit()

    # Perform Query Attack
    perform_attacks(args, tp_apks, model, output_result_dir)


def initialize_dataset(args):
    logging.info(green('Load the apk data...'))
    dataset = APKSET(config['meta_data'], args.dataset)

    logging.info(green('Split the data set...'))
    dataset.split_the_dataset()

    if config['extract_feature']:
        logging.info(green('Extract the apk feature...'))
        dataset.extract_the_feature(args.detection)
    else:
        logging.info(green('Load the apk feature...'))
        dataset.collect_the_feature(args.detection)
        dataset.load_the_feature(args.detection)

    return dataset


def build_and_test_model(args, dataset):
    logging.info(green('Train the target model...'))
    model = Detector("_".join([args.detection, args.dataset, args.classifier]), config['saved_models'],
                     args.detection, args.classifier)
    model.build_classifier(dataset)

    logging.info(green('Test the target model...'))
    y_pred, y_scores = test_model(args, model)

    tps = np.where((model.y_test & y_pred) == 1)[0]
    tp_apks = [dataset.test_set[i] for i in tps]

    report = calculate_base_metrics(model, y_pred, y_scores)
    report['number_of_apps'] = {'train': len(model.y_train),
                                'test': len(model.y_test),
                                'tps': len(tp_apks)}

    logging.info(blue('Performance before attack:\n' + pformat(report)))
    return model


def test_model(args, model):
    if args.classifier in ["svm", "mlp", "rf", "3nn", "fd-vae-mlp"]:
        y_pred = model.clf.predict(model.X_test)
        y_scores = (model.clf.decision_function(model.X_test)
                    if args.classifier == "svm" else model.clf.predict_proba(model.X_test))
    else:
        raise ValueError(f"Unsupported classifier: {args.classifier}")

    assert y_pred is not None
    return y_pred, y_scores


def prepare_tp_apks(args, dataset, model):
    tps = np.where((model.y_test & model.clf.predict(model.X_test)) == 1)[0]
    tp_apks = [dataset.test_set[i] for i in tps]

    if len(tp_apks) > args.attack_num:
        tp_apks = random.sample(tp_apks, args.attack_num)

    return tp_apks


def perform_attacks(args, tp_apks, model, output_result_dir):
    if args.ADZ_attack:
        perform_attack_stage(AdvDroidZero_attacker, 'AdvDroidZero Attack',
                             tp_apks, model, args.query_budget, output_result_dir, config)

    if args.MCTS_attack:
        perform_attack_stage(MCTS_attacker, 'Monte-Carlo Tree Search Attack',
                             tp_apks, model, args.query_budget, output_result_dir, config)

    if args.RSA_attack:
        perform_attack_stage(random_select_attacker, 'Random Attack', tp_apks,
                             model, args.query_budget, output_result_dir, config)

    if args.HRAT_attack:
        perform_attack_stage(HRAT_attacker, 'Structural Attack against Graph Based Android Malware Detectors',
                             tp_apks, model, args.query_budget, output_result_dir, config)

    if args.OB_attack:
        perform_attack_stage(obfuscation_attack, 'Obfuscation Attack using Obfuscapk',
                             tp_apks, model, args.query_budget, output_result_dir, config)


# Define a general function to handle the attack stage
def perform_attack_stage(attack_function, attack_name, apks, model, query_budget, output_result_dir, config):
    logging.info(blue(f'Begin Stage ------- {attack_name}'))
    show_logging(logging.INFO)
    if config['serial']:
        for apk in apks:
            attack_function(apk, model, query_budget, output_result_dir)
    else:
        with mp.Pool(processes=config['nproc_attacker']) as p:
            p.starmap(attack_function, zip(apks, repeat(model),
                      repeat(query_budget), repeat(output_result_dir)))


def prepare_res_save_dir(args):
    """ Prepare the attack result saving dir """
    # Ensure all necessary directories exist
    dirs_to_create = [
        config['saved_models'],
        config['saved_features'],
        os.path.join(config['saved_features'], 'drebin'),
        os.path.join(config['saved_features'], 'drebin_total'),
        os.path.join(config['saved_features'], 'mamadroid'),
        os.path.join(config['saved_features'], 'mamadroid_total'),
        os.path.join(config['saved_features'], 'fd-vae'),
        os.path.join(config['saved_features'], 'fd-vae_total'),
        os.path.join(config['saved_features'], 'apigraph'),
        os.path.join(config['saved_features'], 'apigraph_total'),
    ]
    for dir_path in dirs_to_create:
        os.makedirs(dir_path, exist_ok=True)

    # Construct the output result directory
    output_result_dir = os.path.join(config['results_dir'], args.dataset,
                                     "_".join(
                                         [args.detection, args.classifier]),
                                     "_".join([args.attacker, str(args.attack_num), str(args.query_budget)]))
    # Ensure the output result directory exists, removing and recreating if necessary
    if os.path.exists(output_result_dir):
        shutil.rmtree(output_result_dir)
    os.makedirs(output_result_dir, exist_ok=True)

    # Create subdirectories for success, fail, and modification crash
    subdirs_to_create = ['success', 'fail', 'modification_crash']
    for subdir in subdirs_to_create:
        os.makedirs(os.path.join(output_result_dir, subdir), exist_ok=True)

    return output_result_dir


def parse_args():
    p = argparse.ArgumentParser()

    # Experiment variables
    p.add_argument('-R', '--run-tag',
                   help='An identifier for this experimental setup/run.')
    p.add_argument('--train_model', action='store_true',
                   help="The training process of the malware detection method.")
    p.add_argument('--create_mps', action='store_true',
                   help="The creating process of the malware perturbation set.")

    # Choose the target android dataset
    p.add_argument('--dataset', type=str, default="Androzoo",
                   help='The target malware dataset.')

    # Choose the target feature extraction method
    p.add_argument('--detection', type=str, default="drebin",
                   help='The target malware feature extraction method.')

    # Choose the target classifier
    p.add_argument('--classifier', type=str, default="svm",
                   help='The target malware classifier.')

    # Choose the attack method
    p.add_argument('--attacker', type=str,
                   default="MCTDroid", help='The attack method.')

    # Attackers
    p.add_argument('--MCTS_attack', action='store_true',
                   help='The Monte-Carlo Tree Search Attack.')
    p.add_argument('--ADZ_attack', action='store_true',
                   help='The AdvDroidZero Attack.')
    p.add_argument('--RSA_attack', action='store_true',
                   help='The Random Select Attack.')
    p.add_argument('--HRAT_attack', action='store_true',
                   help='Structural Attack against Graph Based Android Malware Detectors.')
    p.add_argument('--OB_attack', action='store_true',
                   help='The Obfuscation Attack, useing Obfuscapk')

    p.add_argument('-N', '--attack_num', type=int,
                   default=100, help='attack apk numbers.')
    p.add_argument('-P', '--query_budget', type=int,
                   default=100, help='The query budget.')

    # Misc
    p.add_argument('-D', '--debug', action='store_true',
                   help='Display log output in console if True.')

    args = p.parse_args()

    return args


if __name__ == '__main__':
    main()
