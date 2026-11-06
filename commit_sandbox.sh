#!/bin/bash

echo "Scanning for modified and untracked changes inside sandbox-cli workspace..."

# Force git to look recursively into untracked folders like tests/
git status --porcelain -uall | grep -E '^(\?\?| M|M ) ' | sed 's/^...//' | while read -r FILE; do
    
    # Strip wrapping quotes if git outputs them for paths containing spaces/special chars
    FILE=$(echo "$FILE" | sed -e 's/^"//' -e 's/"$//')

    # Guard against directories, bytecode caches, or our own runner script
    if [ -d "$FILE" ] || [[ "$FILE" == *__pycache__* ]] || [[ "$FILE" == "commit_sandbox.sh" ]]; then
        continue
    fi

    # Dynamically structure granular, descriptive commit messages based on CLI layer paths
    if [[ "$FILE" == src/*.rs ]]; then
        MSG="Core Engineering: Enhancing underlying Rust core backend, cryptographic processing routines, or data vault security matrices inside $FILE"
    elif [[ "$FILE" == sandbox_cli/*.py ]]; then
        MSG="Interface Refactoring: Progressing terminal user interface interactive widgets, command routing pipelines, and layout rendering updates inside $FILE"
    elif [[ "$FILE" == tests/*.py ]]; then
        MSG="Quality Assurance: Implementing regression testing suites, unit validation metrics, and boundary runtime assertions inside $FILE integration layer"
    elif [[ "$FILE" == "Cargo.toml" ]] || [[ "$FILE" == "pyproject.toml" ]]; then
        MSG="Configuration Management: Structural project manifest synchronization and dependency ecosystem configuration block adjustments inside $FILE"
    else
        MSG="Maintenance Update: Staging routine tracking updates, operational rule validation parameters, or documentation alignment matrix records for utility asset $FILE"
    fi

    echo "Staging file: $FILE"
    git add "$FILE"

    echo "Committing with detailed message: '$MSG'"
    git commit -m "$MSG"
    
    echo "----------------------------------------------------------------------"
done

# Push the final chain of individual commits to the repository remote
echo "Pushing all individual sandbox-cli commits sequentially generated to the remote repository branch..."
git push
