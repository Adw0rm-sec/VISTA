#!/bin/bash

# Script to push VISTA to GitHub with build pipeline

echo "🚀 Pushing VISTA to GitHub..."
echo ""

# Add all files
echo "📦 Adding all files..."
git add .

# Show status
echo ""
echo "📋 Files to be committed:"
git status --short

# Commit
echo ""
read -p "Enter commit message (or press Enter for default): " commit_msg
if [ -z "$commit_msg" ]; then
    commit_msg="feat: add comprehensive build pipeline and CI/CD workflows"
fi

echo ""
echo "💾 Committing with message: $commit_msg"
git commit -m "$commit_msg"

# Push
echo ""
echo "⬆️  Pushing to GitHub..."
git push -u origin main

echo ""
echo "✅ Done! Your code is now on GitHub."
echo ""
echo "🔗 Repository: https://github.com/Adw0rm-sec/VISTA"
echo "🔧 Actions: https://github.com/Adw0rm-sec/VISTA/actions"
echo ""
echo "The build pipeline will automatically:"
echo "  • Build the JAR file"
echo "  • Run tests and security scans"
echo "  • Commit the built JAR to builds/ directory"
echo "  • Create artifacts for download"
