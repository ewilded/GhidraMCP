# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

## This is Laurie's server with two additional sets of additions from ewilded
# 1. read_data (very useful)
# 2. kd.exe integration (very useful)

import sys
import os
import requests
import argparse
import logging
import time
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
KD_SERVICE_DIR = "C:\\Users\\a739959\\RESEARCH\\TRC\\VULNDEV_FACTORY\\windbg_scripts\\"
KD_INPUT_FILE = os.path.join(KD_SERVICE_DIR, "kd_input")
KD_OUTPUT_FILE = os.path.join(KD_SERVICE_DIR, "kd_output")
KD_POLL_INTERVAL = 0.7  # it was initially set to 500ms (matching service poll rate), increasing it reduces the problem of not getting command output in response to the request sending it, which happens if the output is not saved in the file in a timeframe shorter than the polling time
KD_DEFAULT_TIMEOUT = 30  # seconds
logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool() # added by ewilded
def read_data(address: str, size: int = 8) -> list:
    """
    Read memory at the given address. Returns formatted hex dump (address, hex bytes, ASCII).

    Args:
    address: Hex address string (e.g., "0x1400c73a0"). Symbol names are not supported.
    size: Number of bytes to read (default: 8)
    
    Returns:
    Formatted hex dump string with address, hex bytes, and ASCII representation
    """
    return safe_get("read_data", {"address": address, "size": size})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)
    #return safe_post("decompile", {"name":name})
    # super weird; in my HTTP bridge the scalar syntax does not work, with Lauries HTTP bridge it works fine; must be the way she implemented the server in Java; either way there is no point in reporting the issue then
    # as a matter of fact, using dictionary format here does NOT work properly wth Laurie's HTTP bridge :D so we must keep this code this way, now it's good

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

## KD SERVICE CLIENT HELPERS (added by ewilded)

def _kd_service_available() -> bool:
    """Check if KD service files exist (service may be running)."""
    return os.path.exists(KD_INPUT_FILE) and os.path.exists(KD_OUTPUT_FILE)

def _kd_send_command_internal(command: str, timeout: int = KD_DEFAULT_TIMEOUT) -> str:
    """
    Internal helper to send a command to the KD service and wait for response.

    Args:
        command: Command to send (debugger command or internal: shutdown, restart)
        timeout: Maximum time to wait for response in seconds

    Returns:
        Response from the KD service. If empty response is received while non-empty response is expected, it may be delayed so try getting it by calling kd_fetch_output method.
    """
    global logger

    if not _kd_service_available():
        return "ERROR: KD service files not found. Is the service running?"

    try:
        # 1. Record current output state
        old_content = ""
        try:
            with open(KD_OUTPUT_FILE, 'r', encoding='utf-8', errors='replace') as f:
                old_content = f.read().strip()
        except IOError:
            pass  # File might be empty or not exist yet

        # 2. Write command to input file
        with open(KD_INPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(command)

        if logger:
            logger.info(f"KD command sent: {command[:100]}...")

        # 3. Poll for response (wait for output to change)
        start_time = time.time()

        while time.time() - start_time < timeout:
            time.sleep(KD_POLL_INTERVAL)

            try:
                with open(KD_OUTPUT_FILE, 'r+', encoding='utf-8', errors='replace') as f:
                    new_content = f.read().strip()
                    f.seek(0)        # Move cursor back to beginning
                    f.truncate()     # Clear the file content
                if new_content != old_content: # response changed
                    if logger:
                        logger.info(f"KD response received ({len(new_content)} chars)")
                    return old_content+new_content
                else:
                    if logger:
                        logger.info(f"KD response (old).")
                    return old_content # doesn't matter which one we return
            except IOError as e:
                if logger:
                    logger.warning(f"KD output read error: {e}")
                continue

        return f"ERROR: Timeout waiting for KD response after {timeout} seconds"

    except IOError as e:
        error_msg = f"ERROR: Failed to communicate with KD service: {e}"
        if logger:
            logger.error(error_msg)
        return error_msg

## KD SERVICE MCP METHODS (added by ewilded)
@mcp.tool()
def kd_send_command(command: str, timeout: int = KD_DEFAULT_TIMEOUT) -> str:
    """
    Send a command to the Windows Kernel Debugger (kd.exe) and return the output.

    The KD service automatically handles target state (paused/running) - if the target
    is running, it will send a break signal before executing your command.

    Commands ending with 'g' (go) will resume target execution and return immediately
    without waiting for output.

    Args:
        command: WinDbg/KD command to execute (e.g., "lm", "!process 0 0", "dt nt!_EPROCESS")
        timeout: Maximum time to wait for response in seconds (default: 30)

    Returns:
        Command output from the debugger, or error message if failed

    Examples:
        kd_send_command("lm")  # List loaded modules
        kd_send_command("!process 0 0")  # List all processes
        kd_send_command("bp nt!NtCreateFile")  # Set breakpoint
        kd_send_command("g")  # Resume execution (returns immediately)
    """
    global logger
    if logger:
        logger.info(f"MCP kd_send_command called: {command[:100]}")
    return _kd_send_command_internal(command, timeout)

@mcp.tool()
def kd_restart() -> str:
    """
    Restart the KD session. This will disconnect from the current target and
    establish a new connection.

    Use this if the debugger becomes unresponsive or you need to reconnect.

    Returns:
        Status message indicating success or failure
    """
    global logger
    if logger:
        logger.info("MCP kd_restart called")
    return _kd_send_command_internal("restart", timeout=60)

@mcp.tool()
def kd_shutdown() -> str:
    """
    Shutdown the KD service gracefully. The target will be left running.

    After shutdown, the KD service must be manually restarted from Windows.

    Returns:
        Status message indicating success or failure
    """
    global logger
    if logger:
        logger.info("MCP kd_shutdown called")
    return _kd_send_command_internal("shutdown", timeout=15)

@mcp.tool()
def kd_fetch_output() -> str:
    """
    Retrieve latest kd.exe output without sending any command.
    
    Returns:
        Raw text output from kd.exe.
    """
    try:
        with open(KD_OUTPUT_FILE, 'r+', encoding='utf-8', errors='replace') as f:
            last_output = f.read().strip()
            f.seek(0)        # Move cursor back to beginning
            f.truncate()     # Clear the file content
        if last_output:
            return last_output
    except IOError as e:
        return f"Error while trying to read "+KD_OUTPUT_FILE
    return ""

@mcp.tool()
def kd_status() -> str:
    """
    Check if the KD service is available and responsive.

    Returns:
        Status message indicating service availability
    """
    if not _kd_service_available():
        return "KD service files not found. Service is not running."

    # Try to read the current output file to see last known state
    try:
        with open(KD_OUTPUT_FILE, 'r', encoding='utf-8', errors='replace') as f:
            last_output = f.read().strip()
        if last_output:
            # Return last few lines as indicator of state
            lines = last_output.split('\n')
            preview = '\n'.join(lines[-5:]) if len(lines) > 5 else last_output
            return f"KD service files present. Last output:\n{preview}"
        else:
            return "KD service files present. Output file is empty (service may be initializing)."
    except IOError as e:
        return f"KD service files present but cannot read output: {e}"

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

