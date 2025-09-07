#!/usr/bin/env python3  # Python shebang
import os  # OS operations
import sys  # System utilities
import json  # JSON handling
import subprocess  # Process execution
import tempfile  # Temporary files
import time  # Time utilities
import traceback  # Error tracking
import logging  # Logging framework
from datetime import datetime  # Date/time
from pathlib import Path  # Path handling

logging.basicConfig(  # Setup logging
    level=logging.DEBUG,  # Debug level
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Log format
    handlers=[
        logging.FileHandler('/code/analysis_debug.log'),  # File handler
        logging.StreamHandler(sys.stdout)  # Console handler
    ]
)
logger = logging.getLogger("docker-analyzer")  # Logger instance


def log_debug(message):  # Debug logging
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]  # Current timestamp
    logger.debug(f"[{timestamp}] {message}")


def log_info(message):  # Info logging
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]  # Current timestamp
    logger.info(f"[{timestamp}] {message}")


def log_error(message):  # Error logging
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]  # Current timestamp
    logger.error(f"[{timestamp}] {message}")


def run_bandit(file_path):  # Run Bandit security scanner
    log_info(f"Starting Bandit security scan on: {file_path}")
    try:
        log_debug(f"Running command: bandit -f json -r {file_path}")
        start_time = time.time()  # Start timer

        result = subprocess.run(  # Execute Bandit
            ["bandit", "-f", "json", "-r", file_path],  # Bandit command
            capture_output=True,  # Capture output
            text=True  # Text mode
        )

        duration = time.time() - start_time  # Calculate duration
        log_debug(f"Bandit completed in {duration:.2f} seconds")

        if result.stdout:  # Check for output
            log_debug(f"Bandit found results")
            try:
                bandit_results = json.loads(result.stdout)  # Parse JSON
                log_debug(
                    f"Bandit found {len(bandit_results.get('results', []))} issues")
                return bandit_results
            except json.JSONDecodeError as e:  # JSON parse error
                log_error(f"Failed to parse Bandit JSON output: {str(e)}")
                return {"results": [], "errors": ["JSON parse error"]}
        else:  # No output
            log_debug("Bandit returned no results")
            if result.stderr:  # Check stderr
                log_error(f"Bandit stderr: {result.stderr}")
            return {"results": [], "errors": []}
    except Exception as e:  # General error
        log_error(f"Error running Bandit: {str(e)}")
        log_error(traceback.format_exc())
        return {"error": str(e), "results": [], "errors": [str(e)]}


def run_safety_check():  # Run Safety dependency checker
    log_info("Starting Safety dependency check")
    try:
        # Create a temporary requirements.txt file
        log_debug("Creating temporary requirements.txt file")
        with open("/code/requirements.txt", "w") as f:  # Create requirements file
            # Extract imports from the code
            log_debug("Extracting imports from code.py")
            try:
                with open("/code/code.py", "r") as code_file:  # Read code file
                    code = code_file.read()  # Get code content
                    imports = []  # Import list
                    for line in code.split("\n"):  # Process each line
                        # Check for imports
                        if line.startswith("import ") or line.startswith("from "):
                            # Extract package name (simplified)
                            if "import " in line:  # Import statement
                                package = line.split("import ")[1].split(
                                    " ")[0].split(".")[0]  # Extract package
                                # Skip stdlib
                                if package not in ["os", "sys", "json", "time", "datetime", "math", "random", "re"]:
                                    imports.append(package)  # Add to list
                                    log_debug(f"Found import: {package}")

                # Write extracted packages to requirements
                for package in imports:  # Write each package
                    f.write(f"{package}\n")

                log_debug(
                    f"Created requirements.txt with {len(imports)} packages")
            except Exception as e:  # Import extraction error
                log_error(f"Error extracting imports: {str(e)}")
                # Create an empty requirements file as fallback
                f.write("# No imports extracted\n")

        # List requirements file content for debugging
        try:
            with open("/code/requirements.txt", "r") as f:  # Read requirements
                req_content = f.read()  # Get content
                log_debug(f"requirements.txt content:\n{req_content}")
        except Exception as e:  # Read error
            log_error(f"Error reading requirements.txt: {str(e)}")

        log_debug("Running safety check command")
        start_time = time.time()  # Start timer

        result = subprocess.run(  # Execute Safety
            ["safety", "check", "--json", "-r",
                "/code/requirements.txt"],  # Safety command
            capture_output=True,  # Capture output
            text=True  # Text mode
        )

        duration = time.time() - start_time  # Calculate duration
        log_debug(f"Safety check completed in {duration:.2f} seconds")

        if result.stdout:  # Check for output
            log_debug("Safety check returned results")
            try:
                safety_results = json.loads(result.stdout)  # Parse JSON
                log_debug(
                    f"Safety found issues in {len(safety_results)} packages")
                return safety_results
            except json.JSONDecodeError as e:  # JSON parse error
                log_error(f"Failed to parse Safety JSON output: {str(e)}")
                return []
        else:  # No output
            log_debug("Safety check returned no results")
            if result.stderr:  # Check stderr
                log_error(f"Safety stderr: {result.stderr}")
            return []
    except Exception as e:  # General error
        log_error(f"Error in safety check: {str(e)}")
        log_error(traceback.format_exc())
        return [{"error": str(e)}]


def run_semgrep():  # Run Semgrep static analyzer
    try:
        result = subprocess.run(  # Execute Semgrep
            ["semgrep", "--config=p/security-audit",
                "--json", "/code"],  # Semgrep command
            capture_output=True,  # Capture output
            text=True  # Text mode
        )
        try:
            # Parse JSON
            return json.loads(result.stdout) if result.stdout else {"results": []}
        except json.JSONDecodeError:  # JSON parse error
            return {"results": []}
    except Exception as e:  # General error
        return {"error": str(e), "results": []}


def execute_code():  # Execute Python code safely
    result = {  # Result dictionary
        "executed": False,  # Execution flag
        "execution_time": 0,  # Execution time
        "errors": [],  # Error list
        "warnings": []  # Warning list
    }

    try:
        os.environ["PYTHONWARNINGS"] = "always"  # Enable warnings

        start_time = time.time()  # Start timer

        try:
            process = subprocess.run(  # Execute Python code
                ["python", "/code/code.py"],  # Python command
                capture_output=True,  # Capture output
                text=True,  # Text mode
                timeout=30  # 30 second timeout
            )
            result["executed"] = True  # Mark as executed
            result["stdout"] = process.stdout  # Capture stdout
            result["stderr"] = process.stderr  # Capture stderr

            if process.stderr:  # Check for stderr
                result["warnings"] = process.stderr.split(
                    "\n")  # Split warnings

            if process.returncode != 0:  # Check return code
                result["errors"].append(
                    f"Process exited with code {process.returncode}")

        except subprocess.TimeoutExpired:  # Timeout error
            result["errors"].append("Execution timed out (30s limit)")
        except Exception as e:  # Execution error
            result["errors"].append(f"Execution error: {str(e)}")

        result["execution_time"] = time.time(
        ) - start_time  # Calculate duration

    except Exception as e:  # General error
        result["errors"].append(f"Analysis error: {str(e)}")

    return result


def generate_report(bandit_results, safety_results, semgrep_results, execution_results):

    vulnerabilities = []
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    if "results" in bandit_results:
        for item in bandit_results["results"]:
            severity = item.get("issue_severity", "medium").lower()
            if severity == "high":
                summary["high"] += 1
            elif severity == "medium":
                summary["medium"] += 1
            elif severity == "low":
                summary["low"] += 1

            vulnerabilities.append({
                "type": f"Bandit: {item.get('test_id', 'Unknown')}",
                "severity": item.get("issue_severity", "Medium"),
                "line": item.get("line_number", 0),
                "description": item.get("issue_text", "Unknown issue"),
                "recommendation": item.get("more_info", "Review the code for security issues")
            })

    for item in safety_results:
        if "vulnerabilities" in item:
            for vuln in item["vulnerabilities"]:
                severity = "high"
                summary["high"] += 1

                vulnerabilities.append({
                    "type": f"Dependency: {vuln.get('package_name', 'Unknown')}",
                    "severity": "High",
                    "line": 0,
                    "description": vuln.get("advisory", "Vulnerable dependency"),
                    "recommendation": f"Update to version {vuln.get('fixed_version', 'latest')}"
                })

    if "results" in semgrep_results:
        for item in semgrep_results["results"]:
            severity = item.get("extra", {}).get("severity", "medium").lower()
            if severity == "critical":
                summary["critical"] += 1
            elif severity == "high":
                summary["high"] += 1
            elif severity == "medium":
                summary["medium"] += 1
            elif severity == "low":
                summary["low"] += 1
            else:
                summary["info"] += 1

            vulnerabilities.append({
                "type": f"Semgrep: {item.get('check_id', 'Unknown')}",
                "severity": item.get("extra", {}).get("severity", "Medium").capitalize(),
                "line": item.get("start", {}).get("line", 0),
                "description": item.get("extra", {}).get("message", "Code issue detected"),
                "recommendation": "Review the code pattern for security issues"
            })

    if execution_results.get("errors"):
        for error in execution_results["errors"]:
            summary["medium"] += 1
            vulnerabilities.append({
                "type": "Runtime Error",
                "severity": "Medium",
                "line": 0,
                "description": error,
                "recommendation": "Fix runtime errors as they could lead to undefined behavior"
            })

    if execution_results.get("warnings"):
        for warning in execution_results.get("warnings", []):
            if warning.strip():
                summary["low"] += 1
                vulnerabilities.append({
                    "type": "Runtime Warning",
                    "severity": "Low",
                    "line": 0,
                    "description": warning,
                    "recommendation": "Address runtime warnings to improve code quality"
                })

    if not vulnerabilities:
        summary["info"] += 1
        vulnerabilities.append({
            "type": "No Vulnerabilities Detected",
            "severity": "Info",
            "line": 0,
            "description": "No security issues were detected during runtime analysis.",
            "recommendation": "Continue following secure coding practices."
        })

    report = {
        "status": "completed",
        "language": "python",
        "scan_type": "runtime",
        "is_vulnerable": any(v["severity"] != "Info" for v in vulnerabilities),
        "summary": summary,
        "vulnerabilities": vulnerabilities,
        "execution_data": {
            "execution_time": execution_results.get("execution_time", 0),
            "executed_successfully": execution_results.get("executed", False)
        }
    }

    return report


def main():

    log_info("=== Starting Security Analysis ===")

    if not os.path.exists("/code/code.py"):
        log_error("Error: /code/code.py not found")
        error_report = {
            "status": "failed",
            "error": "Code file not found",
            "is_vulnerable": False,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
            "vulnerabilities": [{
                "type": "File Error",
                "severity": "Info",
                "line": 0,
                "description": "The code file was not found for analysis.",
                "recommendation": "Make sure the file is properly uploaded."
            }]
        }
        with open("/code/vulnerability_report.json", "w") as f:
            json.dump(error_report, f, indent=4)
        log_info("Created error report for missing file")
        return 1

    try:
        file_size = os.path.getsize("/code/code.py")
        log_info(f"Analyzing code.py: {file_size} bytes")

        with open("/code/code.py", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[:10]
            log_debug(f"First 10 lines of code.py:\n{''.join(lines)}")
    except Exception as e:
        log_error(f"Error reading code file: {str(e)}")

    try:
        log_info("Running Bandit security check")
        bandit_results = run_bandit("/code/code.py")

        log_info("Running Safety dependency check")
        safety_results = run_safety_check()

        log_info("Running Semgrep check")
        semgrep_results = run_semgrep()

        log_info("Running code execution test")
        execution_results = execute_code()

        log_info("Generating final report")
        report = generate_report(
            bandit_results, safety_results, semgrep_results, execution_results)

        with open("/code/vulnerability_report.json", "w") as f:
            json.dump(report, f, indent=4)

        log_info("Analysis completed successfully")

        debug_info = {
            "bandit_raw": bandit_results,
            "safety_raw": safety_results,
            "semgrep_raw": semgrep_results,
            "execution_raw": execution_results,
            "timestamp": datetime.now().isoformat()
        }

        with open("/code/debug_info.json", "w") as f:
            json.dump(debug_info, f, indent=4)

        log_info("Debug info saved to debug_info.json")

        return 0
    except Exception as e:
        log_error(f"Unhandled exception in main: {str(e)}")
        log_error(traceback.format_exc())

        error_report = {
            "status": "failed",
            "error": str(e),
            "is_vulnerable": False,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
            "vulnerabilities": [{
                "type": "Analysis Error",
                "severity": "Info",
                "line": 0,
                "description": f"Error: {str(e)}",
                "recommendation": "Internal analyzer error. Please try again or contact support."
            }]
        }

        with open("/code/vulnerability_report.json", "w") as f:
            json.dump(error_report, f, indent=4)

        return 1


if __name__ == "__main__":
    sys.exit(main())
