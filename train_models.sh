#!/bin/bash

# Malware Detection Method Building Stage
# if you want to train the models, please make sure config['extract_feature'] is set to False

models=("drebin" "apigraph" "mamadroid" "fd-vae")

declare -A model_classifier_map=(
    ["drebin"]="svm mlp"
    ["apigraph"]="svm"
    ["mamadroid"]="rf 3nn"
    ["fd-vae"]="fd-vae-mlp"
)

for model in "${!model_classifier_map[@]}"; do
    for classifier in ${model_classifier_map[$model]}; do
        if ! python main.py -R "${model}-${classifier}" \
            --train_model \
            -D \
            --detection "$model" \
            --classifier "$classifier" \
            --dataset "Drebin"; then
            echo "Task failed for model: $model, classifier: $classifier. Continuing..."
        fi
    done
done
