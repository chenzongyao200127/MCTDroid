#!/bin/bash

# Common parameters
PYTHON_CMD="python main.py"
COMMON_PARAMS="-N 100 --attacker ADZ --ADZ_attack"
P_VALUES=(10 50 100)

# Function to run experiments for a given configuration
run_experiments() {
    local run_tag=$1
    local detection=$2
    local classifier=$3

    for p in "${P_VALUES[@]}"; do
        echo "Running experiment: $run_tag with P=$p"
        $PYTHON_CMD -R "$run_tag" $COMMON_PARAMS \
            --detection "$detection" \
            --classifier "$classifier" \
            -P "$p"
    done
}

# Run experiments for different configurations
run_experiments "drebin-SVM-ADZ" "drebin" "svm"

# Mamadroid-RF experiments
run_experiments "mamadroid-RF-ADZ" "mamadroid" "rf"

# Mamadroid-3NN experiments  
run_experiments "mamadroid-3nn-ADZ" "mamadroid" "3nn"