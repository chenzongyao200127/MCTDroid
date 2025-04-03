#!/bin/bash

# Malware Detection Method Building Stage
# if you want to train the models, please make sure config['extract_feature'] is set to False

dataset="Androzoo"

declare -A model_classifier_map=(
    ["drebin"]="svm mlp"
    ["apigraph"]="svm"
    ["mamadroid"]="rf 3nn"
    ["fd-vae"]="fd-vae-mlp"
)

for model in "${!model_classifier_map[@]}"; do
    classifiers="${model_classifier_map[$model]}"
    for classifier in $classifiers; do
        if ! python main.py -R "${model}-${classifier}" \
            --train_model \
            -D \
            --detection "$model" \
            --classifier "$classifier" \
            --dataset "$dataset"; then
            echo "Task failed for model: $model, classifier: $classifier. Continuing..."
        fi
    done
done
