import os
import logging
import re
import numpy as np
import traceback
from androguard.misc import AnalyzeAPK
from settings import config
from utils import red, green

# Precompiled regex for finding intent actions in the manifest
INTENT_ACTION_PATTERN = re.compile('action\s+android:name=\"(?P<action>.+)\"')


def get_vae_fd_feature(apk_path, output_path=None):
    """
    Extract VAE-based feature descriptor from an APK file.
    
    Args:
        apk_path: Path to the APK file
        output_path: Optional path to save the extracted features
        
    Returns:
        numpy.ndarray: Feature vector containing binary encodings of permissions, 
                      actions, and API calls
    """
    # Initialize feature vector
    total_feature = []
    
    try:
        # Analyze the APK file
        a, d, dx = AnalyzeAPK(apk_path)

        # Process permissions
        with open(config['vae_permissions'], "r") as f:
            total_permissions = [line.strip() for line in f]
            
        apk_permissions = {permission.split(".")[-1] for permission in a.get_permissions()}
        
        for permission in total_permissions:
            total_feature.append(1 if permission in apk_permissions else 0)

        # Process intent actions
        with open(config['vae_actions'], "r") as f:
            total_actions = [line.strip() for line in f]
            
        android_manifest = a.get_android_manifest_axml().get_xml().decode()
        apk_actions = {match.group('action').split('.')[-1] 
                      for match in INTENT_ACTION_PATTERN.finditer(android_manifest)}
        
        for action in total_actions:
            total_feature.append(1 if action in apk_actions else 0)

        # Process API calls
        with open(config['vae_apis'], "r") as f:
            total_apis = [line.strip() for line in f]
            
        apk_methods = {f"{method.get_method().get_class_name()}->{method.get_method().get_name()}" 
                      for method in dx.find_methods('.*', '.*', '.*', '.*')}
        
        for api in total_apis:
            total_feature.append(1 if api in apk_methods else 0)
            
    except Exception:
        logging.error(red(f"Error occurred in APK: {os.path.basename(apk_path)}"))
        traceback.print_exc()
        
        # Ensure consistent feature vector size on error
        expected_size = 147 + 126 + 106  # permissions + actions + apis
        total_feature = [0] * expected_size

    # Ensure consistent feature vector size
    expected_size = 147 + 126 + 106
    if len(total_feature) < expected_size:
        total_feature = [0] * expected_size

    # Convert to numpy array
    total_feature = np.array(total_feature, dtype=np.int)
    
    # Save features if output path is provided
    if output_path is not None:
        np.savez(output_path, vae_fd_feature=total_feature)
        logging.critical(green(f'Successfully saved the vae-fd feature in: {output_path}'))
        
    return total_feature
