#!/bin/bash

# # Define the base command with common parameters
# BASE_CMD="python main.py -R drebin-SVM-MCTS -N 100 --detection drebin --classifier svm --attacker MCTDroid --MCTS_attack"

# # Run the commands with varying -P values
# $BASE_CMD -P 10
# $BASE_CMD -P 50
# $BASE_CMD -P 100

BASE_CMD="python main.py -R mamadroid-RF-MCTS -N 100 --detection mamadroid --classifier rf --attacker MCTDroid --MCTS_attack"

# Run the commands with varying -P values
$BASE_CMD -P 10
# $BASE_CMD -P 50
# $BASE_CMD -P 100

BASE_CMD="python main.py -R mamadroid-3nn-MCTS -N 100 --detection mamadroid --classifier 3nn --attacker MCTDroid --MCTS_attack"

# Run the commands with varying -P values
# $BASE_CMD -P 10
$BASE_CMD -P 50
$BASE_CMD -P 100

