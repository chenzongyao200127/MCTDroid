#!/bin/bash

# Common parameters
PYTHON_CMD="python main.py"
COMMON_PARAMS="-N 100 --attacker MCTDroid --MCTS_attack"
P_VALUES=(10 50 100)

# Function to run experiments for a given configuration
run_experiments() {
    local run_tag=$1
    local detection=$2
    local classifier=$3
    local p_values=("${@:4}")

    for p in "${p_values[@]}"; do
        echo "Running experiment: $run_tag with P=$p"
        $PYTHON_CMD -R "$run_tag" $COMMON_PARAMS \
            --detection "$detection" \
            --classifier "$classifier" \
            -P "$p"
    done
}

# Mamadroid-RF experiments (only P=10)
run_experiments "mamadroid-RF-MCTS" "mamadroid" "rf" 10

# Mamadroid-3NN experiments (P=50,100)
run_experiments "mamadroid-3nn-MCTS" "mamadroid" "3nn" 50 100

# Drebin-SVM experiments are commented out but can be enabled by uncommenting:
# run_experiments "drebin-SVM-MCTS" "drebin" "svm" "${P_VALUES[@]}"
