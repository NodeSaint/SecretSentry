#!/bin/bash
# Test runner script for Secrets Sentry

set -e  # Exit on error

echo "================================"
echo "Secrets Sentry Test Suite"
echo "================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if virtual environment is activated
if [[ -z "${VIRTUAL_ENV}" ]]; then
    echo -e "${YELLOW}Warning: No virtual environment detected${NC}"
    echo "Consider activating a virtual environment first"
    echo ""
fi

# Parse command line arguments
FAST_MODE=false
COVERAGE=true
PARALLEL=false
MARKERS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --fast)
            FAST_MODE=true
            shift
            ;;
        --no-coverage)
            COVERAGE=false
            shift
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --unit)
            MARKERS="-m unit"
            shift
            ;;
        --integration)
            MARKERS="-m integration"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--fast] [--no-coverage] [--parallel] [--unit] [--integration]"
            exit 1
            ;;
    esac
done

# Install test dependencies if needed
if ! python -c "import pytest" 2>/dev/null; then
    echo -e "${YELLOW}Installing test dependencies...${NC}"
    pip install -q -r requirements-test.txt
    echo ""
fi

# Build pytest command
PYTEST_CMD="pytest"

if [ "$FAST_MODE" = true ]; then
    echo -e "${YELLOW}Running in fast mode (no slow tests)${NC}"
    PYTEST_CMD="$PYTEST_CMD -m 'not slow'"
fi

if [ "$COVERAGE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=src --cov-report=term-missing --cov-report=html"
fi

if [ "$PARALLEL" = true ]; then
    echo -e "${YELLOW}Running tests in parallel${NC}"
    PYTEST_CMD="$PYTEST_CMD -n auto"
fi

if [ -n "$MARKERS" ]; then
    PYTEST_CMD="$PYTEST_CMD $MARKERS"
fi

# Run tests
echo -e "${GREEN}Running tests...${NC}"
echo "Command: $PYTEST_CMD"
echo ""

if $PYTEST_CMD; then
    echo ""
    echo -e "${GREEN}✓ All tests passed!${NC}"

    if [ "$COVERAGE" = true ]; then
        echo ""
        echo "Coverage report generated:"
        echo "  - Terminal: (shown above)"
        echo "  - HTML: htmlcov/index.html"
        echo "  - XML: coverage.xml"
    fi

    exit 0
else
    echo ""
    echo -e "${RED}✗ Tests failed${NC}"
    exit 1
fi
