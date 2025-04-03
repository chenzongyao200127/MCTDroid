#!/bin/bash
# before perform attack, please make sure PerturbationSelector has been structured

# Common parameters
PYTHON_CMD="python main.py"
P_VALUES=(10 20 30 40 50 100)

# Attack configurations
declare -A attack_params=(
    ["ADZ"]="-N 100 --attacker ADZ --ADZ_attack"
    # ["RSA"]="-N 100 --attacker RSA --RSA_attack"
)

# Models and their classifiers
declare -A model_classifier_map=(
    ["drebin"]="svm mlp"
    ["apigraph"]="svm"
    ["mamadroid"]="rf 3nn"
    ["fd-vae"]="fd-vae-mlp"
)

# Function to run experiments for a given configuration
run_experiments() {
    local model=$1
    local classifier=$2
    local attack=$3
    local params=$4

    for p in "${P_VALUES[@]}"; do
        echo "Running experiment: $model-$classifier with $attack and P=$p"
        $PYTHON_CMD -R "$model-$classifier-$attack-P$p" $params \
            --detection "$model" \
            --classifier "$classifier" \
            -P "$p"
    done
}

# Run experiments for all models, classifiers, and attacks
for attack in "${!attack_params[@]}"; do
    for model in "${!model_classifier_map[@]}"; do
        for classifier in ${model_classifier_map[$model]}; do
            run_experiments "$model" "$classifier" "$attack" "${attack_params[$attack]}"
        done
    done
done