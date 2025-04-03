#!/bin/bash
# before perform attack, please make sure PerturbationSelector has been structured

# Common parameters
PYTHON_CMD="python main.py"
COMMON_PARAMS="-N 100 --attacker ADZ --ADZ_attack"
P_VALUES=(10 30 50 100)

# Models and their classifiers
declare -A model_classifier_map=(
    ["drebin"]="svm mlp"
    # ["apigraph"]="svm"
    ["mamadroid"]="rf 3nn"
    ["fd-vae"]="fd-vae-mlp"
)

# Function to run experiments for a given configuration
run_experiments() {
    local model=$1
    local classifier=$2

    for p in "${P_VALUES[@]}"; do
        echo "Running experiment: $model-$classifier with P=$p"
        $PYTHON_CMD -R "$model-$classifier-P$p" $COMMON_PARAMS \
            --detection "$model" \
            --classifier "$classifier" \
            -P "$p"
    done
}

# Run experiments for all models and their classifiers
for model in "${!model_classifier_map[@]}"; do
    for classifier in ${model_classifier_map[$model]}; do
        run_experiments "$model" "$classifier"
    done
done