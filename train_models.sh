#!/bin/bash

# Malware Detection Method Building Stage

# models: apigraph, drebin, mamadroid, fd-vae
# classifiers: rf, svm, 3nn, mlp

models=("apigraph" "drebin" "mamadroid" "fd-vae")
classifiers=("rf" "svm" "3nn" "mlp")

for model in "${models[@]}"; do
    for classifier in "${classifiers[@]}"; do
        python main.py -R "${model}-feature" \
            --train_model \
            -D \
            --detection "$model" \
            --classifier "$classifier" \
            --dataset "Drebin" || echo "Task failed for model: $model, classifier: $classifier. Continuing..."
    done
done
