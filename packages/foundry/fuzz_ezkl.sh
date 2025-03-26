RANDOM_STRING=$(openssl rand -base64 6)
ARTIFACT_NAME=balancer_fee_model
USER_ID=8c9f812f-b85e-47d6-9fca-c4f9b34622b7
DEPLOYMENT_NAME=0195d1ec-e714-72e4-baef-578131cc7f39
MAX_ITERATIONS=5
DELAY_BETWEEN_RUNS=10

check_status() {
    local output
    output=$(archon get -q $USER_ID)

    if echo "$output" | grep -q "STATUS: complete"; then
        echo "Task completed successfully."
        return 0
    else
        echo "Task did not complete successfully."
        return 1
    fi
}

run_workflow() {
    local iteration=$1
    echo "==============================================="
    echo "Starting iteration $iteration at $(date)"
    echo "==============================================="

    archon job -a $ARTIFACT_NAME -q $USER_ID -d $DEPLOYMENT_NAME gen-random-data -D input_$RANDOM_STRING.json --min 80000000000 --max 1000000000000
    archon get -q $USER_ID -p
    check_status || { echo "Random data generation failed. Exiting iteration."; return 1; }


    archon job -a $ARTIFACT_NAME -q $USER_ID -d $DEPLOYMENT_NAME gen-witness -D input_$RANDOM_STRING.json -O witness_$RANDOM_STRING.json
    archon get -q $USER_ID -p
    check_status || { echo "Witness generation failed. Exiting iteration."; return 1; }


    archon job -a $ARTIFACT_NAME -q $USER_ID -d $DEPLOYMENT_NAME prove -W witness_$RANDOM_STRING.json --proof-path proof_$RANDOM_STRING.json
    archon get -q $USER_ID -p
    check_status || { echo "Proof creation failed. Exiting iteration."; return 1; }


    archon job -a $ARTIFACT_NAME -q $USER_ID -d $DEPLOYMENT_NAME verify --proof-path proof_$RANDOM_STRING.json
    archon get -q $USER_ID -p
    check_status || { echo "Proof verification failed. Exiting iteration."; return 1; }

}

# Main loop
iteration=1
success_count=0
failure_count=0

while [ $iteration -le $MAX_ITERATIONS ]; do
    if run_workflow $iteration; then
        success_count=$((success_count + 1))
    else
        failure_count=$((failure_count + 1))
    fi

    iteration=$((iteration + 1))

    # Only delay if not the last iteration
    if [ $iteration -le $MAX_ITERATIONS ]; then
        sleep $DELAY_BETWEEN_RUNS
    fi
done