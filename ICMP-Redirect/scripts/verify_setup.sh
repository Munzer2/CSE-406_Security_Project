#!/bin/bash

# ICMP Redirect Attack - Complete Setup Verification
# This script verifies that the entire project setup is correct

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}======================================================"
    echo -e "$1"
    echo -e "======================================================${NC}"
}

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header "ICMP Redirect Attack - Setup Verification"

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$PROJECT_DIR/src"

print_status "Project directory: $PROJECT_DIR"

# 1. Check project structure
print_status "Verifying project structure..."
required_files=(
    "$PROJECT_DIR/README.md"
    "$PROJECT_DIR/src/attacker.py"
    "$PROJECT_DIR/src/victim.py"
    "$PROJECT_DIR/src/target.py"
    "$PROJECT_DIR/src/util.py"
    "$PROJECT_DIR/src/verify_packets.py"
    "$PROJECT_DIR/scripts/setup_environment.sh"
    "$PROJECT_DIR/scripts/check_environment.sh"
    "$PROJECT_DIR/scripts/demo_attack.sh"
    "$PROJECT_DIR/scripts/verify_setup.sh"
    "$PROJECT_DIR/scripts/cleanup_docker_environment.sh"
)

missing_files=0
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        print_error "Missing: $(basename "$file")"
        ((missing_files++))
    fi
done

if [ $missing_files -eq 0 ]; then
    print_status "✓ All required files present"
else
    print_error "$missing_files files are missing!"
    exit 1
fi

# 2. Check script permissions
print_status "Checking script permissions..."
scripts=("$PROJECT_DIR/scripts"/*.sh)
non_executable=0
for script in "${scripts[@]}"; do
    if [ ! -x "$script" ]; then
        print_warning "Not executable: $(basename "$script")"
        ((non_executable++))
    fi
done

if [ $non_executable -eq 0 ]; then
    print_status "✓ All scripts are executable"
else
    print_warning "$non_executable scripts need executable permissions"
    print_status "Run: chmod +x scripts/*.sh"
fi

# 3. Check Python file syntax
print_status "Checking Python file syntax..."
python_errors=0
for py_file in "$SRC_DIR"/*.py; do
    if [ -f "$py_file" ]; then
        if ! python3 -m py_compile "$py_file" 2>/dev/null; then
            print_error "Syntax error in $(basename "$py_file")"
            ((python_errors++))
        fi
    fi
done

if [ $python_errors -eq 0 ]; then
    print_status "✓ All Python files have valid syntax"
else
    print_error "$python_errors Python files have syntax errors!"
fi

# 4. Check Docker availability
print_status "Checking Docker availability..."
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    print_error "Docker daemon is not running"
    exit 1
fi

print_status "✓ Docker is available and running"

# 5. Check if containers exist and are healthy
print_status "Checking container status..."
containers=("victim" "router" "target" "attacker")
running_containers=0
for container in "${containers[@]}"; do
    if docker ps -q -f name="$container" | grep -q .; then
        ((running_containers++))
    fi
done

if [ $running_containers -eq 4 ]; then
    print_status "✓ All containers are running"
    
    # Check if files are present in containers
    print_status "Checking files in containers..."
    python_files=("victim.py" "attacker.py" "target.py" "util.py" "verify_packets.py")
    missing_in_containers=0
    
    for container in "${containers[@]:0:3}"; do  # Skip router for file check
        for file in "${python_files[@]}"; do
            if ! docker exec "$container" test -f "/root/$file" 2>/dev/null; then
                print_warning "$file missing in $container"
                ((missing_in_containers++))
            fi
        done
    done
    
    if [ $missing_in_containers -eq 0 ]; then
        print_status "✓ All required files present in containers"
    else
        print_warning "$missing_in_containers files missing in containers"
        print_status "Re-run setup script: sudo ./scripts/setup_environment.sh"
    fi
    
elif [ $running_containers -gt 0 ]; then
    print_warning "$running_containers/4 containers are running"
    print_status "Run: sudo ./scripts/setup_environment.sh"
else
    print_status "No containers running (this is normal for initial setup)"
    print_status "Run: sudo ./scripts/setup_environment.sh"
fi

# 6. Final summary
print_header "Setup Verification Summary"

total_issues=0
total_issues=$((total_issues + missing_files))
total_issues=$((total_issues + python_errors))

if [ $total_issues -eq 0 ]; then
    echo -e "${GREEN}✓ Project setup is complete and ready!${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    if [ $running_containers -eq 4 ]; then
        echo -e "  1. Run demo: ${YELLOW}sudo ./scripts/demo_attack.sh${NC}"
        echo -e "  2. Check status: ${YELLOW}sudo ./scripts/check_environment.sh${NC}"
        echo -e "  3. Manual testing: See README.md for instructions"
    else
        echo -e "  1. Set up environment: ${YELLOW}sudo ./scripts/setup_environment.sh${NC}"
        echo -e "  2. Check status: ${YELLOW}sudo ./scripts/check_environment.sh${NC}"
        echo -e "  3. Run demo: ${YELLOW}sudo ./scripts/demo_attack.sh${NC}"
    fi
else
    echo -e "${RED}✗ $total_issues issues found that need to be resolved${NC}"
    exit 1
fi
