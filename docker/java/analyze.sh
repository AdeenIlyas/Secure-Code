#!/bin/bash  # Bash shebang

cat > /code/vulnerability_report.json << EOL  # Create initial report
{
    "status": "completed",  # Analysis status
    "language": "java",  # Programming language
    "scan_type": "runtime",  # Analysis type
    "is_vulnerable": false,  # Vulnerability flag
    "vulnerabilities": [],  # Vulnerability list
    "summary": {  # Summary counts
        "critical": 0,  # Critical issues
        "high": 0,  # High severity
        "medium": 0,  # Medium severity
        "low": 0,  # Low severity
        "info": 1  # Info messages
    },
    "note": "Analysis started",  # Status note
    "execution_data": {  # Execution info
        "executed_successfully": true  # Success flag
    }
}
EOL

trap 'echo "{\"status\": \"failed\", \"error\": \"$?\", \"language\": \"java\"}" > /code/vulnerability_report.json' ERR  # Error handler

set -e  # Exit on error

handle_error() {  # Error handling function
    echo "Error: $1"  # Print error
    JSON="{\"status\": \"failed\", \"error\": \"$1\", \"language\": \"java\"}"  # Error JSON
    echo $JSON > /code/vulnerability_report.json  # Write error report
    exit 1  # Exit with error
}

echo "Starting Java security analysis..."  # Start message

JAVA_FILES=$(find /code -maxdepth 1 -name "*.java")  # Find Java files
if [ -z "$JAVA_FILES" ]; then  # Check if files found
    handle_error "No Java source files found"  # No files error
fi

echo "Found Java files: $JAVA_FILES"  # List found files

mkdir -p /code/build  # Create build directory

for FILE in $JAVA_FILES; do  # Process each Java file
    FILENAME=$(basename "$FILE" .java)  # Get filename without extension
    
    cp "$FILE" "/code/temp_${FILENAME}.java"  # Create temp copy
    TEMP_FILE="/code/temp_${FILENAME}.java"  # Temp file path
    
    sed -i 's/^package.*;//' "$TEMP_FILE"  # Remove package declaration
    
    if grep -q "public class" "$TEMP_FILE"; then  # Check for public class
        echo "Modifying $TEMP_FILE to have class name: $FILENAME"  # Modify class name
        sed -i "s/public class [A-Za-z0-9_]*/public class $FILENAME/g" "$TEMP_FILE"  # Replace class name
    fi
done

TEMP_FILES=$(find /code -maxdepth 1 -name "temp_*.java")  # Get temp files
echo "Compiling modified Java files..."  # Compile message
if javac -d /code/build $TEMP_FILES 2>/code/compile_errors_mod.txt; then  # Try modified compilation
    echo "Compilation successful with modified files!"  # Success message
    JAVA_FILES=$TEMP_FILES  # Use temp files
else  # Modified compilation failed
    echo "Modified compilation failed, trying original files..."  # Try original
    rm -rf /code/build  # Clean build dir
    mkdir -p /code/build  # Recreate build dir
    if javac -d /code/build $JAVA_FILES 2>/code/compile_errors_orig.txt; then  # Try original compilation
        echo "Compilation successful with original files!"  # Success message
    else  # Both failed
        echo "Both compilation approaches failed. Errors from original files:"  # Show errors
        cat /code/compile_errors_orig.txt  # Display errors
        handle_error "Compilation failed. Please check your Java code for errors."  # Handle error
    fi
fi

echo "Looking for main class in compiled files..."  # Find main class
MAIN_CLASS=""  # Main class variable

for CLASS in $(find /code/build -name "*.class" | sed 's/\.class$//' | sed 's/.*build\///' | tr '/' '.'); do  # Find classes
    if javap -cp /code/build $CLASS 2>/dev/null | grep -q "public static void main(java.lang.String\[\])"; then  # Check for main method
        MAIN_CLASS="$CLASS"  # Set main class
        echo "Found main class: $MAIN_CLASS"  # Found message
        break  # Exit loop
    fi
done

if [ -z "$MAIN_CLASS" ]; then  # No main method found
    MAIN_CLASS=$(find /code/build -name "*.class" | head -1 | sed 's/\.class$//' | sed 's/.*build\///' | tr '/' '.')  # Use first class
    echo "No main method found, using first class: $MAIN_CLASS"  # Use first class
fi

echo "Running FindSecBugs analysis..."  # Start FindSecBugs
SPOTBUGS_PATH="/opt/spotbugs-4.7.3/bin/spotbugs"  # SpotBugs path

if [ ! -f "$SPOTBUGS_PATH" ]; then  # Check if SpotBugs exists
    echo "Warning: SpotBugs not found at expected path. Checking alternatives..."  # Look for alternatives
    SPOTBUGS_PATH=$(find /opt -name "spotbugs" -type f -executable | head -1)  # Find SpotBugs
    
    if [ -z "$SPOTBUGS_PATH" ]; then  # Not found
        echo "SpotBugs not found. Skipping FindSecBugs analysis."  # Skip analysis
    else  # Found
        echo "Found SpotBugs at: $SPOTBUGS_PATH"  # Found message
    fi
fi

if [ -n "$SPOTBUGS_PATH" ] && [ -f "$SPOTBUGS_PATH" ]; then  # Run SpotBugs if available
    "$SPOTBUGS_PATH" \  # Execute SpotBugs
        -textui \  # Text UI mode
        -effort:max \  # Maximum effort
        -pluginList /opt/findsecbugs/findsecbugs-cli-1.12.0.jar \  # FindSecBugs plugin
        -xml:withMessages \  # XML output with messages
        -output /code/findsecbugs-results.xml \  # Output file
        /code/build || echo "FindSecBugs completed with warnings"  # Run or show warnings
else  # SpotBugs not available
    echo "SpotBugs not available. Skipping FindSecBugs analysis."  # Skip message
fi

echo "Running Semgrep analysis..."  # Start Semgrep
semgrep --config=p/java --config=p/security-audit --json /code > /code/semgrep-results.json || echo "Semgrep completed with warnings"  # Run Semgrep

echo "Executing Java program for runtime analysis..."  # Start runtime analysis
RUNTIME_LOG="/code/runtime.log"  # Runtime log file
START_TIME=$(date +%s.%N)  # Start timestamp

echo "Running class: $MAIN_CLASS"  # Run message
timeout 30s java -cp /code/build $MAIN_CLASS > $RUNTIME_LOG 2>&1 || echo "Program execution completed with non-zero exit code: $?"  # Execute with timeout

END_TIME=$(date +%s.%N)  # End timestamp

if command -v bc > /dev/null; then  # Check if bc available
    EXECUTION_TIME=$(echo "$END_TIME - $START_TIME" | bc)  # Calculate execution time
else  # bc not available
    EXECUTION_TIME=0  # Default time
    echo "Warning: 'bc' command not found, using default execution time"  # Warning message
fi

echo "Generating vulnerability report..."  # Generate report
cat > /code/vulnerability_report.json << EOL  # Create final report
{
    "status": "completed",  # Analysis status
    "language": "java",  # Programming language
    "scan_type": "runtime",  # Analysis type
    "is_vulnerable": false,  # Vulnerability flag
    "vulnerabilities": [],  # Vulnerability list
    "summary": {  # Summary counts
        "critical": 0,  # Critical issues
        "high": 0,  # High severity
        "medium": 0,  # Medium severity
        "low": 0,  # Low severity
        "info": 1  # Info messages
    },
    "execution_data": {  # Execution info
        "execution_time": $EXECUTION_TIME,  # Execution time
        "executed_successfully": true  # Success flag
    }
}
EOL

if [ -f /code/findsecbugs-results.xml ]; then  # Check if FindSecBugs results exist
    HIGH_COUNT=$(grep -c "RANK=\"1\"" /code/findsecbugs-results.xml || echo "0")  # Count high severity
    MEDIUM_COUNT=$(grep -c "RANK=\"2\"" /code/findsecbugs-results.xml || echo "0")  # Count medium severity
    LOW_COUNT=$(grep -c "RANK=\"3\"" /code/findsecbugs-results.xml || echo "0")  # Count low severity
    
    if ! jq --arg high "$HIGH_COUNT" --arg medium "$MEDIUM_COUNT" --arg low "$LOW_COUNT" \  # Update JSON with counts
       '.summary.high = ($high | tonumber) | .summary.medium = ($medium | tonumber) | .summary.low = ($low | tonumber)' \
       /code/vulnerability_report.json > /code/temp_report.json; then  # Update report
        echo "Warning: Error updating summary counts with jq. Using default values."  # Error message
        cp /code/vulnerability_report.json /code/temp_report.json  # Use original
    else  # Success
        mv /code/temp_report.json /code/vulnerability_report.json  # Replace report
    fi
    
    echo "Processing FindSecBugs results..."  # Process results
    if [ "$(grep -c "<BugInstance" /code/findsecbugs-results.xml)" -gt 0 ]; then  # Check for bugs
        grep -A 10 "<BugInstance" /code/findsecbugs-results.xml | while read -r line; do  # Process each bug
            if [[ $line == *"<BugInstance"* ]]; then  # Bug instance line
                BUG_TYPE=$(echo $line | grep -o 'type="[^"]*"' | cut -d'"' -f2)  # Extract bug type
                BUG_RANK=$(echo $line | grep -o 'rank="[^"]*"' | cut -d'"' -f2)  # Extract bug rank
                # Map rank to severity
                if [ "$BUG_RANK" == "1" ]; then  # High rank
                    SEVERITY="High"  # High severity
                elif [ "$BUG_RANK" == "2" ]; then  # Medium rank
                    SEVERITY="Medium"  # Medium severity
                else  # Low rank
                    SEVERITY="Low"  # Low severity
                fi
              
                LINE_NUMBER=$(grep -A 5 "$BUG_TYPE" /code/findsecbugs-results.xml | grep "LineNumber" | grep -o ">[0-9]*<" | tr -d '<>' || echo "0")  # Extract line number
                MESSAGE=$(grep -A 5 "$BUG_TYPE" /code/findsecbugs-results.xml | grep "<Message>" | sed 's/<[^>]*>//g' | tr -d '\n' || echo "Security issue detected")  # Extract message
                
                TEMP_JSON="/code/vuln_temp.json"  # Temporary JSON file
                cat > "$TEMP_JSON" << EOL  # Create vulnerability entry
{
    "type": "FindSecBugs: ${BUG_TYPE}",  # Bug type
    "severity": "${SEVERITY}",  # Severity level
    "line": ${LINE_NUMBER:-0},  # Line number
    "description": "Security issue detected",
    "recommendation": "Review code for security issues"
}
EOL
                
                if ! jq --slurpfile vuln "$TEMP_JSON" '.vulnerabilities += $vuln' /code/vulnerability_report.json > /code/temp_report.json; then
                    echo "Warning: Error adding vulnerability with jq. Skipping this finding."
                    cp /code/vulnerability_report.json /code/temp_report.json
                else
                    mv /code/temp_report.json /code/vulnerability_report.json
                fi
            fi
        done
    fi
fi

if [ -f /code/semgrep-results.json ]; then
    echo "Processing Semgrep results..."
    
    if ! jq '.' /code/semgrep-results.json > /dev/null 2>&1; then
        echo "Warning: Semgrep output is not valid JSON. Skipping Semgrep results."
    else
        if jq -e '.results | length > 0' /code/semgrep-results.json > /dev/null 2>&1; then
            jq -r '.results[] | "\(.check_id)|\(.severity // "INFO")|\(.start.line // 0)|\(.message // "Security issue")" 2>/dev/null' /code/semgrep-results.json | \
            while IFS="|" read -r CHECK_ID SEVERITY LINE_NUMBER MESSAGE; do
                # Map severity
                if [ "$SEVERITY" == "ERROR" ]; then
                    SEVERITY="High"
                elif [ "$SEVERITY" == "WARNING" ]; then
                    SEVERITY="Medium"
                else
                    SEVERITY="Low"
                fi
                
                TEMP_JSON="/code/semgrep_vuln.json"
                cat > "$TEMP_JSON" << EOL
{
    "type": "Semgrep: ${CHECK_ID}",
    "severity": "${SEVERITY}",
    "line": ${LINE_NUMBER:-0},
    "description": "Potential security issue detected",
    "recommendation": "Review code pattern for security issues"
}
EOL
                
                if ! jq --slurpfile vuln "$TEMP_JSON" '.vulnerabilities += $vuln' /code/vulnerability_report.json > /code/temp_report.json; then
                    echo "Warning: Error adding Semgrep finding. Skipping this vulnerability."
                    cp /code/vulnerability_report.json /code/temp_report.json
                else
                    mv /code/temp_report.json /code/vulnerability_report.json
                    
                    if [ "$SEVERITY" == "High" ]; then
                        FIELD="high"
                    elif [ "$SEVERITY" == "Medium" ]; then
                        FIELD="medium"
                    else
                        FIELD="low"
                    fi
                    
                    if ! jq --arg field "$FIELD" '.summary[$field] += 1' /code/vulnerability_report.json > /code/temp_report.json; then
                        echo "Warning: Error updating summary count. Using previous report."
                    else
                        mv /code/temp_report.json /code/vulnerability_report.json
                    fi
                fi
            done
        else
            echo "No Semgrep findings to process."
        fi
    fi
fi

if [ -f "$RUNTIME_LOG" ] && [ -s "$RUNTIME_LOG" ]; then
    if grep -q "Exception" "$RUNTIME_LOG" || grep -q "Error" "$RUNTIME_LOG"; then
        echo "Runtime exceptions detected"
        EXCEPTION=$(grep -A 3 "Exception" "$RUNTIME_LOG" | head -n 4 | tr '\n' ' ' | cut -c 1-200 || echo "Runtime exception detected")
        
        TEMP_JSON="/code/exception_vuln.json"
        cat > "$TEMP_JSON" << EOL
{
    "type": "Runtime Exception",
    "severity": "Medium",
    "line": 0,
    "description": "Runtime exception detected",
    "recommendation": "Fix runtime exceptions to prevent security issues"
}
EOL
        
        if ! jq --slurpfile vuln "$TEMP_JSON" '.vulnerabilities += $vuln | .summary.medium += 1' /code/vulnerability_report.json > /code/temp_report.json; then
            echo "Warning: Error adding runtime exception. Using simpler approach."
            cp /code/vulnerability_report.json /code/temp_report.json
        else
            mv /code/temp_report.json /code/vulnerability_report.json
        fi
    fi
fi

if jq -e '.vulnerabilities | length == 0' /code/vulnerability_report.json > /dev/null 2>&1; then
    TEMP_JSON="/code/info_vuln.json"
    cat > "$TEMP_JSON" << EOL
{
    "type": "No Vulnerabilities Detected",
    "severity": "Info",
    "line": 0,
    "description": "No security issues were detected during runtime analysis.",
    "recommendation": "Continue following secure coding practices."
}
EOL
    
    if ! jq --slurpfile info "$TEMP_JSON" '.vulnerabilities += $info | .summary.info += 1' /code/vulnerability_report.json > /code/temp_report.json; then
        echo "Warning: Error adding info entry. Using manual approach."
        cat > /code/vulnerability_report.json << EOL
{
    "status": "completed",
    "language": "java",
    "scan_type": "runtime",
    "is_vulnerable": false,
    "vulnerabilities": [
        {
            "type": "No Vulnerabilities Detected",
            "severity": "Info",
            "line": 0,
            "description": "No security issues were detected during runtime analysis.",
            "recommendation": "Continue following secure coding practices."
        }
    ],
    "summary": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 1
    }
}
EOL
    else
        mv /code/temp_report.json /code/vulnerability_report.json
    fi
fi

if grep -q "\"severity\": \"High\"" /code/vulnerability_report.json || \
   grep -q "\"severity\": \"Medium\"" /code/vulnerability_report.json || \
   grep -q "\"severity\": \"Low\"" /code/vulnerability_report.json; then
    
    if ! jq '. + {"is_vulnerable": true}' /code/vulnerability_report.json > /code/temp_report.json; then
        echo "Warning: Error setting is_vulnerable flag. Creating new report."
        echo "{\"status\": \"completed\", \"language\": \"java\", \"is_vulnerable\": true}" > /code/vulnerability_report.json
    else
        mv /code/temp_report.json /code/vulnerability_report.json
    fi
else
    if ! jq '. + {"is_vulnerable": false}' /code/vulnerability_report.json > /code/temp_report.json; then
        echo "Warning: Error setting is_vulnerable flag. Creating new report."
        echo "{\"status\": \"completed\", \"language\": \"java\", \"is_vulnerable\": false}" > /code/vulnerability_report.json
    else
        mv /code/temp_report.json /code/vulnerability_report.json
    fi
fi

echo "Java security analysis completed!"
exit 0 