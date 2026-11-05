#!/bin/bash

# Array of files to commit individually
FILES=(
    "src/crypto.rs"
    "src/lib.rs"
    "src/vault.rs"
    "sandbox_cli/__init__.py"
    "sandbox_cli/main.py"
    "sandbox_cli/ui.py"
)

# Loop through each file
for FILE in "${FILES[@]}"; do
    # Check if the file exists and has changes
    if [ -f "$FILE" ]; then
        echo "Adding $FILE..."
        git add "$FILE"
        
        # Commit with a custom message including the file name
        git commit -m "Update: $FILE"
        
        echo "----------------------------------------"
    else
        echo "Skipping $FILE (file not found)"
    fi
done

# Optional: Push all commits at the end
echo "Pushing all individual commits to the repository..."
git push

