<%doc>
Inferno AI - System Master Template

This master template provides the structure for constructing system prompts
for Inferno's agentic security assessment flows.

The structure includes the following sections:

1. Instructions: Base agent instructions provided via system_prompt variable
   that define the role, behavior, and operational guidelines.

2. Compacted Summary (optional): AI-generated summary from previous
   conversations to reduce context usage and maintain continuity.

3. Memory (optional): Past experiences retrieved from Mem0/Qdrant vector
   database for context augmentation and learning from previous sessions.

4. Reasoning (optional): Additional thought processes from reasoning-type
   LLM models (which could be different from the selected model) to
   augment context with deeper analysis.

5. Environment: Details about the execution environment including OS,
   IPs, available tools, wordlists, etc.

Variables available:
- system_prompt: Base agent instructions (REQUIRED)
- compacted_summary: AI-generated conversation summary (optional)
- memory: Past experiences from vector database (optional)
- rag_enabled: Whether RAG/memory is enabled (bool)
- reasoning_content: Reasoning from specialized models (optional)
- env_context: Whether to include environment context ("true"/"false")
- hostname: Machine hostname
- ip_addr: Default IP address
- tun0_addr: VPN/CTF interface IP (optional)
- os_name: Operating system name
- os_version: OS version
- seclist_dirs: List of seclists directories
- wordlist_files: List of available wordlists
- ctf_inside: CTF environment flag
- ctf_name: Name of CTF challenge (if applicable)
- target: Target being assessed
- objective: Assessment objective

Inspired by CAI's system_master_template.md pattern.
</%doc>
<%
    import os
    import platform
    import socket
    from pathlib import Path

    # Get environment context setting (default to true)
    env_context_setting = env_context if 'env_context' in dir() else os.getenv('INFERNO_ENV_CONTEXT', 'true')

    # Helper function for safe variable access
    def safe_get(var_name, default=''):
        return locals().get(var_name) or globals().get(var_name) or default

    # Check if reasoning content is available
    has_reasoning = 'reasoning_content' in dir() and reasoning_content is not None

    # Check if compacted summary is available
    has_compacted = 'compacted_summary' in dir() and compacted_summary

    # Check if memory is available
    has_memory = 'rag_enabled' in dir() and rag_enabled and 'memory' in dir() and memory
%>
## System Instructions

${system_prompt}
% if has_compacted:

<compacted_context>
This is a summary of previous conversation context that has been compacted to save tokens:

${compacted_summary}

Use this summary to understand the context and continue from where the conversation left off.
</compacted_context>
% endif
% if has_memory:

<memory>
${memory}
</memory>

Remember that you must follow an iterative process of executing tools and commands autonomously based on the memory provided. While each session starts fresh, the memory shows successful steps that were previously completed. The reconnaissance information and discovered attack paths remain relevant, so avoid repeating unnecessary steps. Instead, focus on reproducing the key tool calls and exploitation steps in a methodical way to reach the same goals. For example, if a vulnerability was previously exploited, execute the specific commands needed to exploit it again. Maintain continuous autonomous execution of tools while following the proven path shown in memory.
% endif

% if has_reasoning:
<reasoning>
${reasoning_content}
</reasoning>
% endif

% if env_context_setting.lower() == 'true':
<%
    # Gather system info safely
    try:
        _hostname = hostname if 'hostname' in dir() else socket.gethostname()
        _ip_addr = ip_addr if 'ip_addr' in dir() else socket.gethostbyname(_hostname)
        _os_name = os_name if 'os_name' in dir() else platform.system()
    except Exception:
        _hostname = "localhost"
        _ip_addr = "127.0.0.1"
        _os_name = "Linux"

    # Get tun0 address
    _tun0_addr = tun0_addr if 'tun0_addr' in dir() else None
    if _tun0_addr is None:
        try:
            import netifaces
            if 'tun0' in netifaces.interfaces():
                addrs = netifaces.ifaddresses('tun0')
                if netifaces.AF_INET in addrs:
                    _tun0_addr = addrs[netifaces.AF_INET][0].get('addr')
        except Exception:
            pass

    # Get wordlist directories
    _seclist_dirs = seclist_dirs if 'seclist_dirs' in dir() else []
    _wordlist_files = wordlist_files if 'wordlist_files' in dir() else []

    if not _seclist_dirs:
        seclists_path = Path('/usr/share/wordlists/seclists')
        if seclists_path.exists():
            _seclist_dirs = [d.name for d in seclists_path.iterdir() if d.is_dir()]

    if not _wordlist_files:
        wordlist_path = Path('/usr/share/wordlists')
        if wordlist_path.exists():
            _wordlist_files = [f.name for f in wordlist_path.iterdir() if f.is_file()][:20]

    # CTF environment
    _ctf_inside = ctf_inside if 'ctf_inside' in dir() else os.getenv('CTF_INSIDE')
    _ctf_name = ctf_name if 'ctf_name' in dir() else os.getenv('CTF_NAME')
%>
Environment context (in "tree" format):
seclists
% if _seclist_dirs:
% for dir_name in _seclist_dirs:
|-- ${dir_name}
% endfor
% else:
|-- (No directories found in seclists)
% endif

- When in doubt, list again.

Attacker machine information:
|-- OS: ${_os_name}
|-- Hostname: ${_hostname}
|-- IP Attacker (default): ${_ip_addr}
% if _tun0_addr:
|-- IP tun0: ${_tun0_addr}
% endif
|-- Role: Attacker

% if _wordlist_files:
Available wordlists (/usr/share/wordlists):
% for file_name in _wordlist_files:
|-- ${file_name}
% endfor
% endif
% if _ctf_inside or _ctf_name:

CTF Environment:
% if _ctf_inside:
|-- CTF Mode: Active
% endif
% if _ctf_name:
|-- Challenge: ${_ctf_name}
% endif
% endif
% endif
