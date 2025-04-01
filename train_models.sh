#!/bin/bash

# Malware Detection Method Building Stage

models=("drebin" "apigraph" "mamadroid" "fd-vae")
classifiers=("svm" "dl" "rf" "3nn" "mlp")

declare -A model_classifier_map=(
    ["drebin"]="svm dl"
    ["apigraph"]="svm"
    ["mamadroid"]="rf 3nn"
    ["fd-vae"]="mlp"
)

for model in "${models[@]}"; do
    for classifier in ${model_classifier_map[$model]}; do
        python main.py -R "${model}-feature" \
            --train_model \
            -D \
            --detection "$model" \
            --classifier "$classifier" \
            --dataset "Drebin" || echo "Task failed for model: $model, classifier: $classifier. Continuing..."
    done
done
