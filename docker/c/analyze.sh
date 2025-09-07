#!/bin/bash  # Bash shebang

set -e  # Exit on error

handle_error() {  # Error handling function
    echo "Error: $1"  # Print error
    JSON="{\"status\": \"failed\", \"error\": \"$1\"}"  # Error JSON
    echo "$JSON" > /code/vulnerability_report.json  # Write error report
    exit 1  # Exit with error
}

echo "Starting C security analysis..."  # Start message

if [ ! -f /code/main.c ]; then  # Check for C source file
    handle_error "C source file not found"  # No file error
fi

# Output files
CPPCHECK_OUTPUT="/code/cppcheck-output.xml"  # Cppcheck results
FLAWFINDER_OUTPUT="/code/flawfinder-output.txt"  # Flawfinder results
COMPILE_OUTPUT="/code/compile-output.txt"  # Compilation output
RUNTIME_OUTPUT="/code/runtime-output.txt"  # Runtime output

# Run Cppcheck
echo "Running Cppcheck for static analysis..."  # Start Cppcheck
cppcheck --enable=all --inconclusive --xml --output-file="$CPPCHECK_OUTPUT" /code/main.c || echo "Cppcheck completed with warnings"  # Run Cppcheck

# Run Flawfinder
echo "Running Flawfinder for security vulnerabilities..."  # Start Flawfinder
flawfinder --html /code/main.c > "$FLAWFINDER_OUTPUT" || echo "Flawfinder completed with warnings"  # Run Flawfinder

# Compile the code
echo "Compiling C code..."  # Start compilation
COMPILATION_SUCCESS=true  # Compilation flag
gcc -Wall -Wextra -pedantic -std=c99 /code/main.c -o /code/program -lmysqlclient 2> "$COMPILE_OUTPUT" || {  # Compile with warnings
    echo "Compilation failed, continuing with static analysis only"  # Compilation failed
    COMPILATION_SUCCESS=false  # Set flag to false
}

# Run the program if compilation succeeded
EXECUTION_TIME=0  # Execution time
if [ "$COMPILATION_SUCCESS" = true ]; then  # Check compilation success
    echo "Executing program for runtime analysis..."  # Start execution
    START_TIME=$(date +%s.%N)  # Start timestamp
    timeout 30s /code/program > "$RUNTIME_OUTPUT" 2>&1 || echo "Program execution completed with non-zero exit code: $?"  # Execute with timeout
    END_TIME=$(date +%s.%N)  # End timestamp
    EXECUTION_TIME=$(echo "$END_TIME - $START_TIME" | bc) || EXECUTION_TIME=0  # Calculate duration
    if [[ $EXECUTION_TIME == .* ]]; then  # Check for leading decimal
        EXECUTION_TIME="0$EXECUTION_TIME"  # Add leading zero
    fi
else  # Compilation failed
    echo "Skipping runtime analysis due to compilation failure"  # Skip runtime
    echo "Compilation failed" > "$RUNTIME_OUTPUT"  # Write failure message
fi

# Initialize vulnerability report
echo "Generating vulnerability report..."  # Start report generation
cat > /code/vulnerability_report.json << EOL  # Create initial report
{
    "status": "completed",  # Analysis status
    "language": "c",  # Programming language
    "scan_type": "static",  # Analysis type
    "vulnerabilities": [],  # Vulnerability list
    "summary": {},  # Summary counts
    "execution_data": {  # Execution info
        "execution_time": ${EXECUTION_TIME:-0},  # Execution time
        "executed_successfully": $COMPILATION_SUCCESS  # Success flag
    }
}
EOL

# Function to add a vulnerability
add_vulnerability() {  # Add vulnerability function
    local TYPE="$1"  # Vulnerability type
    local SEVERITY="$2"  # Severity level
    local LINE="$3"  # Line number
    local DESCRIPTION="$4"  # Description
    local RECOMMENDATION="$5"  # Recommendation
    
    if [ -z "$LINE" ] || ! [[ "$LINE" =~ ^[0-9]+$ ]]; then  # Validate line number
        LINE="0"  # Default line number
    fi
    
    TEMP_REPORT=$(mktemp)  # Temporary report file
    TEMP_VULN=$(mktemp)  # Temporary vulnerability file
    
    cat > "$TEMP_VULN" << EOL  # Create vulnerability entry
{
    "type": "$TYPE",  # Vulnerability type
    "severity": "$SEVERITY",  # Severity level
    "line": $LINE,  # Line number
    "description": "$DESCRIPTION",  # Description
    "recommendation": "$RECOMMENDATION"  # Recommendation
}
EOL
    
    jq --argjson vuln "$(cat "$TEMP_VULN")" '.vulnerabilities += [$vuln]' /code/vulnerability_report.json > "$TEMP_REPORT"  # Add to report
    mv "$TEMP_REPORT" /code/vulnerability_report.json  # Replace report
    rm -f "$TEMP_VULN"  # Clean up temp file
}

# Process Cppcheck results
if [ -f "$CPPCHECK_OUTPUT" ]; then  # Check if Cppcheck results exist
    echo "Processing Cppcheck results..."  # Process results
    ERROR_COUNT=$(grep -c "<error " "$CPPCHECK_OUTPUT" || echo "0")  # Count errors
    if [ "$ERROR_COUNT" -gt 0 ]; then  # Check for errors
        grep -A 10 "<error " "$CPPCHECK_OUTPUT" | while read -r line; do  # Process each error
            if [[ $line == *"<error "* ]]; then  # Error line
                SEVERITY=$(echo "$line" | grep -o 'severity="[^"]*"' | cut -d'"' -f2)  # Extract severity
                MAP_SEVERITY=$([ "$SEVERITY" = "error" ] && echo "High" || [ "$SEVERITY" = "warning" ] && echo "Medium" || echo "Low")  # Map severity
                MSG=$(echo "$line" | grep -o 'msg="[^"]*"' | cut -d'"' -f2)  # Extract message
                LINE=$(echo "$line" | grep -o 'line="[^"]*"' | cut -d'"' -f2)  # Extract line number
                LINE=${LINE:-0}  # Default line number
                add_vulnerability "Cppcheck: $SEVERITY" "$MAP_SEVERITY" "$LINE" "$MSG" "Fix the identified issue following security best practices"  # Add vulnerability
            fi
        done
    fi
fi

# Process Flawfinder results
if [ -f "$FLAWFINDER_OUTPUT" ]; then  # Check if Flawfinder results exist
    echo "Processing Flawfinder results..."  # Process results
    grep -A 2 "Hits =.*" "$FLAWFINDER_OUTPUT" | while read -r line; do  # Process each hit
        if [[ $line == *"Hits ="* ]]; then  # Hit line
            FUNC_LINE=$(echo "$line" | grep -o "[^(]*([^)]*" | head -1)  # Extract function line
            LINE_NUM=$(echo "$FUNC_LINE" | grep -o ":[0-9]*" | cut -d':' -f2)  # Extract line number
            LINE_NUM=${LINE_NUM:-0}  # Default line number
            LEVEL=$(echo "$line" | grep -o "Level [0-9]" | cut -d' ' -f2)  # Extract level
            SEVERITY=$([ "$LEVEL" = "5" ] || [ "$LEVEL" = "4" ] && echo "High" || [ "$LEVEL" = "3" ] && echo "Medium" || echo "Low")  # Map severity
            read -r DESC_LINE  # Read description line
            DESC=$(echo "$DESC_LINE")  # Get description
            add_vulnerability "Flawfinder: Level $LEVEL" "$SEVERITY" "$LINE_NUM" "$DESC" "Review and fix the identified security vulnerability"  # Add vulnerability
        fi
    done
fi

# Process compilation warnings/errors
if [ -f "$COMPILE_OUTPUT" ] && [ -s "$COMPILE_OUTPUT" ]; then  # Check compilation output
    echo "Processing compilation warnings and errors..."  # Process compilation issues
    grep "error:" "$COMPILE_OUTPUT" | while read -r line; do  # Process errors
        LINE_NUM=$(echo "$line" | grep -o ":[0-9]*:" | head -1 | grep -o "[0-9]*")  # Extract line number
        LINE_NUM=${LINE_NUM:-0}  # Default line number
        MSG=$(echo "$line" | sed 's/.*error: //')  # Extract error message
        add_vulnerability "Compilation Error" "High" "$LINE_NUM" "$MSG" "Fix compilation errors as they may lead to undefined behavior or security issues"  # Add vulnerability
    done
    grep "warning:" "$COMPILE_OUTPUT" | while read -r line; do  # Process warnings
        LINE_NUM=$(echo "$line" | grep -o ":[0-9]*:" | head -1 | grep -o "[0-9]*")  # Extract line number
        LINE_NUM=${LINE_NUM:-0}  # Default line number
        MSG=$(echo "$line" | sed 's/.*warning: //')  # Extract warning message
        add_vulnerability "Compilation Warning" "Medium" "$LINE_NUM" "$MSG" "Address compiler warnings to improve code quality and prevent potential issues"  # Add vulnerability
    done
    if [ "$COMPILATION_SUCCESS" = false ]; then  # Check compilation failure
        add_vulnerability "Compilation Failure" "High" "0" "The code failed to compile" "Fix the compilation errors before deployment"  # Add vulnerability
    fi
fi

# Check for runtime issues
if [ "$COMPILATION_SUCCESS" = true ] && [ -f "$RUNTIME_OUTPUT" ] && [ -s "$RUNTIME_OUTPUT" ]; then  # Check runtime output
    echo "Processing runtime output..."  # Process runtime issues
    SEGFAULT=$(grep -c "Segmentation fault" "$RUNTIME_OUTPUT" || echo "0")  # Count segfaults
    ABORTED=$(grep -c "Aborted" "$RUNTIME_OUTPUT" || echo "0")  # Count aborts
    FLOATING=$(grep -c "Floating point exception" "$RUNTIME_OUTPUT" || echo "0")  # Count floating point exceptions
    SEGFAULT=${SEGFAULT:-0}  # Default segfault count
    ABORTED=${ABORTED:-0}  # Default abort count
    FLOATING=${FLOATING:-0}  # Default floating point count
    if [ "$SEGFAULT" -gt 0 ]; then  # Check for segfaults
        add_vulnerability "Runtime Error" "High" "0" "Segmentation fault detected during execution" "Check for null pointer dereferences, buffer overflows, or use-after-free issues"  # Add vulnerability
    fi
    if [ "$ABORTED" -gt 0 ]; then  # Check for aborts
        add_vulnerability "Runtime Error" "High" "0" "Program aborted during execution" "Check for failed assertions or other runtime errors"  # Add vulnerability
    fi
    if [ "$FLOATING" -gt 0 ]; then  # Check for floating point exceptions
        add_vulnerability "Runtime Error" "High" "0" "Floating point exception occurred during execution" "Check for division by zero or other invalid floating-point operations"  # Add vulnerability
    fi
fi

TEMP_REPORT=$(mktemp)  # Temporary report file
jq '  # Update summary counts
    .summary.critical = (.vulnerabilities | map(select(.severity == "Critical")) | length),  # Count critical
    .summary.high = (.vulnerabilities | map(select(.severity == "High")) | length),  # Count high
    .summary.medium = (.vulnerabilities | map(select(.severity == "Medium")) | length),  # Count medium
    .summary.low = (.vulnerabilities | map(select(.severity == "Low")) | length),  # Count low
    .summary.info = (.vulnerabilities | map(select(.severity == "Info")) | length)  # Count info
' /code/vulnerability_report.json > "$TEMP_REPORT"  # Update report
mv "$TEMP_REPORT" /code/vulnerability_report.json  # Replace report

VULN_COUNT=$(jq '.vulnerabilities | length' /code/vulnerability_report.json)  # Count vulnerabilities
TEMP_REPORT=$(mktemp)  # Temporary report file
if [ "$VULN_COUNT" -gt 0 ]; then  # Check for vulnerabilities
    HIGH_COUNT=$(jq '.summary.high' /code/vulnerability_report.json)  # Count high severity
    MEDIUM_COUNT=$(jq '.summary.medium' /code/vulnerability_report.json)  # Count medium severity
    if [ "$HIGH_COUNT" -gt 0 ] || [ "$MEDIUM_COUNT" -gt 0 ]; then  # Check for high/medium issues
        jq '.is_vulnerable = true' /code/vulnerability_report.json > "$TEMP_REPORT"  # Mark as vulnerable
    else  # No high/medium issues
        jq '.is_vulnerable = false' /code/vulnerability_report.json > "$TEMP_REPORT"  # Mark as not vulnerable
    fi
else  # No vulnerabilities
    jq '.is_vulnerable = false' /code/vulnerability_report.json > "$TEMP_REPORT"  # Mark as not vulnerable
fi
mv "$TEMP_REPORT" /code/vulnerability_report.json  # Replace report

if [ "$VULN_COUNT" -eq 0 ]; then
    echo "No vulnerabilities found, adding info entry..."
    add_vulnerability "No Vulnerabilities Detected" "Info" "0" "No security issues were detected during static or runtime analysis." "Continue following secure coding practices"
    TEMP_REPORT=$(mktemp)
    jq '.summary.info = 1' /code/vulnerability_report.json > "$TEMP_REPORT"
    mv "$TEMP_REPORT" /code/vulnerability_report.json
fi

echo "C security analysis completed!"
exit 0