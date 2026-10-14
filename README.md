## Getting Started
### Prerequisite:
In order to run this agent you need to have ollama installed (see the official guide here https://ollama.com/download)
```
ollama pull llama3.1
```
### 1. Clone the Repository
```bash
git clone https://github.com/danithen/reimagined-lamp
cd reimagined-lamp
```

### 2. Configure Environment
Create a .env file in the root directory:
```bash
touch .env
```
Add the following variables:
```env
# Ollama Configuration
OLLAMA_BASE_URL=http://host.docker.internal:11434

# LangSmith Tracing (Optional)
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=your_langsmith_key_here
LANGCHAIN_PROJECT="pi-nvd-agent"
```

### 3. Launch the Agent
Build and start the container:
```bash
docker-compose up --build -d
```

### 4. Interact with the Agent
Since this is an interactive CLI tool, you must attach to the running container:
```bash
docker attach pi-nvd-agent
```

**Usage:**
- Enter a CVE ID (e.g., CVE-2021-44228) when prompted.
- Review the agent's analysis.
- Type yes to approve the assessment or provide specific corrections (e.g., "The asset W05 is actually patched").
- Type exit to quit.

*(To detach from the container without stopping it, press Ctrl+P then Ctrl+Q)*.

---

## Risk Rating Logic

The agent applies the following policy:

| Rating | Criteria |
| :--- | :--- |
| High | Prerequisites are confirmed AND exploitation would cause major business harm (e.g., Identity outage). |
| Medium | Prerequisites are confirmed AND consequences are meaningful but not catastrophic. |
| Low | Evidence establishes required conditions are absent, or consequences are minor. |
| Insufficient | Material uncertainty prevents a decision; requires manual analyst review. |
## Agent Diagram
<img width="2224" height="2104" alt="image" src="https://github.com/user-attachments/assets/66991ea8-b433-4560-adea-2d9bfb960cdf" />

## Project Structure
- index.ts: Core agent logic, LangGraph workflow, and CLI interface.
- Dockerfile: Multi-stage build for a lightweight Node.js runtime.
- docker-compose.yml: Infrastructure config for containerized execution.
- ENVIRONMENT_DATA: Simulated asset inventory and evidence register for Northbridge Services.
