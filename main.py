import random
import os
import logging
import numpy as np
import multiprocessing as mp
from itertools import repeat
from pprint import pformat
from settings import config
from utils import blue, green, calculate_base_metrics, configure_logging
from datasets.apks import APKSET
from defender.detector import Detector
from mps.components import get_candidate_benign_components
from attacker.mcts import MCTS_attacker
from attacker.adz import AdvDroidZero_attacker
from attacker.ra import Random_attacker
from androguard.core.androconf import show_logging

# Set random seed for reproducibility
random.seed(42)

CLASSIFIER_CONFIGS = {
    "svm": lambda model: (model.clf.predict(model.X_test), 
                         model.clf.decision_function(model.X_test)),
    "mlp": lambda model: (model.clf.predict(model.X_test), 
                         model.clf.predict_proba(model.X_test)),
    "rf": lambda model: (model.clf.predict(model.X_test), 
                        model.clf.predict_proba(model.X_test)),
    "3nn": lambda model: (model.clf.predict(model.X_test), 
                         model.clf.predict_proba(model.X_test))
}

def create_directory(path):
    """Create directory if it doesn't exist"""
    os.makedirs(path, exist_ok=True)

def setup_result_directories(base_dir):
    """Create required subdirectories for results"""
    for subdir in ["success", "fail", "modification_crash"]:
        create_directory(os.path.join(base_dir, subdir))

def get_model_predictions(model, classifier):
    """Get model predictions based on classifier type"""
    if classifier not in CLASSIFIER_CONFIGS:
        raise ValueError(f"Unsupported classifier: {classifier}")
    return CLASSIFIER_CONFIGS[classifier](model)

def perform_attack_stage(attack_function, attack_name, apks, model, query_budget, output_result_dir, config):
    """Execute attack stage either serially or in parallel"""
    logging.info(blue(f'Begin Stage ------- {attack_name}'))
    show_logging(logging.INFO)
    
    if config['serial']:
        for apk in apks:
            attack_function(apk, model, query_budget, output_result_dir)
    else:
        with mp.Pool(processes=config['nproc_attacker']) as pool:
            pool.starmap(attack_function, zip(apks, repeat(model),
                      repeat(query_budget), repeat(output_result_dir)))

def prepare_res_save_dir(args):
    """Prepare directory structure for saving results"""
    # Create base directories
    for path in [config['saved_models'], config['saved_features']]:
        create_directory(path)

    # Create feature directories
    feature_types = ['drebin', 'drebin_total', 'mamadroid', 'mamadroid_total']
    for feature in feature_types:
        create_directory(os.path.join(config['saved_features'], feature))

    # Setup results directory
    output_result_dir = os.path.join(
        config['results_dir'], 
        args.dataset,
        "_".join([args.detection, args.classifier]),
        "_".join([args.attacker, str(args.attack_num), str(args.query_budget)])
    )
    
    if os.path.exists(output_result_dir):
        shutil.rmtree(output_result_dir)
    create_directory(output_result_dir)
    setup_result_directories(output_result_dir)
    
    return output_result_dir

def parse_args():
    """Parse command line arguments with improved organization"""
    import argparse
    parser = argparse.ArgumentParser(description='Malware Detection and Attack Framework')
    
    # Experiment settings
    exp_group = parser.add_argument_group('Experiment Settings')
    exp_group.add_argument('-R', '--run-tag', help='Identifier for this experimental setup/run')
    exp_group.add_argument('--train_model', action='store_true', help='Train the malware detection method')
    exp_group.add_argument('--create_mps', action='store_true', help='Create malware perturbation set')
    
    # Model configuration
    model_group = parser.add_argument_group('Model Configuration') 
    model_group.add_argument('--dataset', default="Androzoo", help='Target malware dataset')
    model_group.add_argument('--detection', default="drebin", help='Target malware feature extraction method')
    model_group.add_argument('--classifier', default="svm", help='Target malware classifier')
    
    # Attack settings
    attack_group = parser.add_argument_group('Attack Settings')
    attack_group.add_argument('--attacker', default="MCTDroid", help='Attack method')
    attack_group.add_argument('--MCTS_attack', action='store_true', help='Use Monte-Carlo Tree Search Attack')
    attack_group.add_argument('--ADZ_attack', action='store_true', help='Use AdvDroidZero Attack')
    attack_group.add_argument('--RA_attack', action='store_true', help='Use Random Attack')
    attack_group.add_argument('-N', '--attack_num', type=int, default=100, help='Number of attacks')
    attack_group.add_argument('-P', '--query_budget', type=int, default=100, help='Query budget per attack')
    
    # Misc
    parser.add_argument('-D', '--debug', action='store_true', help='Enable console logging')
    
    return parser.parse_args()

def main():
    args = parse_args()
    configure_logging(args.run_tag, args.debug)
    output_result_dir = prepare_res_save_dir(args)

    logging.info(blue('Begin Stage ------- Building the Malware Detection Methods'))
    
    # Initialize and prepare dataset
    dataset = APKSET(config['meta_data'], args.dataset)
    dataset.split_the_dataset()

    if config['extract_feature']:
        logging.info(green('Extract the apk feature...'))
        dataset.extract_the_feature(args.detection)
        return

    # Load and process features
    dataset.collect_the_feature(args.detection)
    dataset.load_the_feature(args.detection)

    # Build and train model
    model = Detector("_".join([args.detection, args.dataset, args.classifier]), 
                    config['saved_models'],
                    args.detection, 
                    args.classifier)
    model.build_classifier(dataset)

    # Get model predictions
    y_pred, y_scores = get_model_predictions(model, args.classifier)
    
    # Process results
    tps = np.where((model.y_test & y_pred) == 1)[0]
    tp_apks = [dataset.test_set[i] for i in tps]
    
    report = calculate_base_metrics(model, y_pred, y_scores)
    report['number_of_apps'] = {
        'train': len(model.y_train),
        'test': len(model.y_test),
        'tps': len(tp_apks)
    }
    logging.info(blue('Performance before attack:\n' + pformat(report)))

    if len(tp_apks) > args.attack_num:
        tp_apks = random.sample(tp_apks, args.attack_num)

    if args.train_model:
        return

    if args.create_mps:
        get_candidate_benign_components()
        return

    # Execute attacks
    attack_configs = [
        (args.ADZ_attack, AdvDroidZero_attacker, 'AdvDroidZero Attack'),
        (args.MCTS_attack, MCTS_attacker, 'Monte-Carlo Tree Search Attack'),
        (args.RA_attack, Random_attacker, 'Random Attack')
    ]

    for should_attack, attacker, name in attack_configs:
        if should_attack:
            perform_attack_stage(attacker, name, tp_apks, model, 
                               args.query_budget, output_result_dir, config)

if __name__ == '__main__':
    main()
