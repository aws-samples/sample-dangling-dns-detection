#!/bin/bash
# Build Lambda deployment package for Dangling DNS Detection
#
# Usage: ./scripts/package.sh [output_dir]
#
# This script creates a deployment package containing the Lambda function
# code and all required dependencies.

set -e

# Configuration
OUTPUT_DIR="${1:-dist}"
PACKAGE_NAME="dangling-dns-detection.zip"
PYTHON_VERSION="python3.11"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building Dangling DNS Detection deployment package...${NC}"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create temporary build directory
BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

echo -e "${YELLOW}Installing dependencies...${NC}"

# Install dependencies to build directory
python3 -m pip install \
    --target "$BUILD_DIR" \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.11 \
    --only-binary=:all: \
    --upgrade \
    boto3 2>/dev/null || python3 -m pip install --target "$BUILD_DIR" boto3

echo -e "${YELLOW}Copying source code...${NC}"

# Copy source code
cp -r src "$BUILD_DIR/"

# Remove unnecessary files
find "$BUILD_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$BUILD_DIR" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find "$BUILD_DIR" -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
find "$BUILD_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true

echo -e "${YELLOW}Creating deployment package...${NC}"

# Create zip package
cd "$BUILD_DIR"
zip -r9 "$PACKAGE_NAME" . -x "*.pyc" -x "*__pycache__*" > /dev/null

# Move to output directory
mv "$PACKAGE_NAME" "$OLDPWD/$OUTPUT_DIR/"
cd "$OLDPWD"

# Get package size
PACKAGE_SIZE=$(du -h "$OUTPUT_DIR/$PACKAGE_NAME" | cut -f1)

echo -e "${GREEN}✓ Deployment package created: $OUTPUT_DIR/$PACKAGE_NAME ($PACKAGE_SIZE)${NC}"
echo ""
echo "Next steps:"
echo "  1. Upload to S3: aws s3 cp $OUTPUT_DIR/$PACKAGE_NAME s3://YOUR_BUCKET/"
echo "  2. Deploy stack: aws cloudformation deploy \\"
echo "       --template-file infrastructure/template.yaml \\"
echo "       --stack-name dangling-dns-detection \\"
echo "       --parameter-overrides LambdaCodeS3Bucket=YOUR_BUCKET \\"
echo "       --capabilities CAPABILITY_NAMED_IAM"
