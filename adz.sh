#!/bin/bash

# Define the base command with common parameters
BASE_CMD="python main.py -R drebin-SVM-ADZ -N 100 --detection drebin --classifier svm --attacker ADZ --ADZ_attack"

# Run the commands with varying -P values
# $BASE_CMD -P 10
# $BASE_CMD -P 50
# $BASE_CMD -P 100

BASE_CMD="python main.py -R mamadroid-RF-ADZ -N 100 --detection mamadroid --classifier rf --attacker ADZ --ADZ_attack"

# Run the commands with varying -P values
$BASE_CMD -P 10
$BASE_CMD -P 50
$BASE_CMD -P 100

BASE_CMD="python main.py -R mamadroid-3nn-ADZ -N 100 --detection mamadroid --classifier 3nn --attacker ADZ --ADZ_attack"

# Run the commands with varying -P values
$BASE_CMD -P 10
$BASE_CMD -P 50
$BASE_CMD -P 100