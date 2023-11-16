#!/bin/bash

# The first argument is the directory to search
dir=$1

# Replace / with _ in the directory name
dir_name=${dir//\//_}

# Find all non-markdown files in the specified directory and its subdirectories
files=$(find $dir -type f -not -name "*.md")

# Create a zip of the found files
zip "slide_${dir_name}_tzx.zip" $files
