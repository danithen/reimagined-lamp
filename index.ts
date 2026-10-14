import { ChatOllama } from "@langchain/ollama";
import { DynamicStructuredTool } from "@langchain/core/tools";
import { StateGraph, Annotation, END } from "@langchain/langgraph";
import { z } from "zod";
import "dotenv/config";
import readline from "node:readline/promises";
import { stdin as inputStdin } from "node:process";
import { stdout as outputStdout } from "node:process";

// --- 🛡️ NORTHBRIDGE ENVIRONMENT KNOWLEDGE BASE ---
const ENVIRONMENT_DATA = {
  assets: {
    "W01": "Domain Controllers (4). Windows Server 2022. AD DS, DNS, Kerberos. (Zone: IDENTITY)",
    "W02": "Certificate Authorities (2). Windows Server 2022. Online issuing CA. (Zone: IDENTITY)",
    "W03": "Directory sync servers (2). Windows Server 2022. Sync to Entra ID. (Zone: IDENTITY)",
    "W04": "DHCP servers (2). Windows Server 2022. (Zone: IDENTITY)",
    "W05": "File Servers (4). Windows Server 2022. SMB 3. FILE04 does NOT require SMB signing. (Zone: APPS)",
    "W06": "Print servers (2). Windows Server 2022. Spooler enabled. (Zone: APPS)",
    "W07": "Config Manager (2). Windows Server 2022. (Zone: APPS)",
    "W08": "Admin jump hosts (2). Windows Server 2022. (Zone: MGMT)",
    "W09": "Backup management (2). Windows Server 2022. Veeam. (Zone: BACKUP)",
    "W10": "RDS hosts (4). Windows Server 2022. (Zone: APPS)",
    "W11": "ERP App Servers (4). Windows Server 2022; IIS 10. (Zone: APPS)",
    "W12": "Prod DB Servers (4). Windows Server 2022; SQL Server 2022. (Zone: DATA)",
    "W13": "Intranet/Portal (4). Windows Server 2022; IIS 10. (Zone: APPS)",
    "W14": "Mgmt DB Servers (2). Windows Server 2022; SQL Server 2022. (Zone: MGMT)",
    "W15": "Legacy Finance (2). Windows Server 2016. NTLM enabled. (Zone: LEGACY)",
    "W16": "Utility servers (6). Windows Server 2022. (Zone: APPS)",
    "W17": "Deployment servers (2). Windows Server 2022. (Zone: APPS)",
    "W18": "Monitoring (2). Windows Server 2022. (Zone: APPS)",
    "L01": "Reverse Proxy (2). Ubuntu 24.04 LTS; nginx. (Zone: DMZ)",
    "L02": "Partner SFTP (2). Ubuntu 24.04 LTS; OpenSSH. (Zone: DMZ)",
    "L03": "Git servers (2). Ubuntu 24.04 LTS; GitLab. (Zone: DMZ)",
    "L04": "Automation runners (2). Ubuntu 24.04 LTS; Docker. (Zone: DMZ)",
    "N02": "VPN Gateways (2). Fortinet FortiGate 100F; FortiOS. (Zone: DMZ)",
  },
  evidence: {
    "S01": "Asset register: 1000 endpoints, 60 server VMs, 32 appliances.",
    "S02": "Network design: Default deny inter-zone traffic. No public RDP, SMB, LDAP, SQL.",
    "S03": "Control register: SMB signing not required on FILE04. 12 E02 sensors stale.",
    "S05": "Business Impact: Identity outage blocks 1000 staff. ERP outage delays orders/invoicing > 4hrs.",
  }
};

// ANSI Color Codes
const RED = "\\x1b[31m";
const RESET = "\\x1b[0m";
const YELLOW = "\\x1b[33m";

// --- STATE DEFINITION ---
const AgentState = Annotation.Root({
  messages: Annotation<any[]>({
    reducer: (x, y) => x.concat(y),
    default: () => [],
  }),
  status: Annotation<string>({
    reducer: (x, y) => y,
    default: () => "start",
  }),
});

// --- TOOLS ---
const cveLookupTool = new DynamicStructuredTool({
  name: "lookup_vulnerability",
  description: "Retrieves vulnerability details from the NVD database using a CVE ID.",
  schema: z.object({ cveId: z.string() }),
  func: async ({ cveId }) => {
    console.log(`[Tool] Fetching NVD data for ${cveId}...`);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const response = await fetch(url);
    
    if (!response.ok) {
      throw new Error(`NVD API responded with status ${response.status}`);
    }
    
    const data = await response.json();
    const vuln = data.vulnerabilities?.[0];
    if (!vuln) {
      throw new Error(`No vulnerability found for ID: ${cveId}`);
    }
    
    const description = vuln.cve.descriptions.find((d: any) => d.lang === "en")?.value || "No description";
    return `CVE ID: ${cveId}\nDescription: ${description}\nMetrics: ${JSON.stringify(vuln.cve.metrics)}`;
  },
});

const envLookupTool = new DynamicStructuredTool({
  name: "lookup_environment",
  description: "Retrieves the full asset inventory or a specific asset/evidence record from Northbridge Services.",
  schema: z.object({ query: z.string().describe("Use 'ALL' for full inventory, or specific IDs like 'W05' or 'S02'") }),
  func: async ({ query }) => {
    console.log(`[Tool] Querying Northbridge Env for: ${query}...`);
    const q = query.toUpperCase();
    if (q === "ALL") return JSON.stringify(ENVIRONMENT_DATA.assets);
    const asset = ENVIRONMENT_DATA.assets[q];
    const evidence = ENVIRONMENT_DATA.evidence[q];
    if (asset) return `Asset ${q}: ${asset} (Source: simulated)`;
    if (evidence) return `Evidence ${q}: ${evidence} (Source: simulated)`;
    return "No record found for that query.";
  },
});

const tools = [cveLookupTool, envLookupTool];

// --- MODEL ---
const model = new ChatOllama({
  model: "llama3.1",
  baseUrl: process.env.OLLAMA_BASE_URL,
  temperature: 0, 
  num_predict: 1024,
}).bindTools(tools);

// --- NODES ---
async function analyzer(state: typeof AgentState.State) {
  const systemPrompt = `You are a Cybersecurity Risk Assessment Agent for Northbridge Services.
  
  YOUR MISSION:
  Perform an environment-wide risk assessment for a specific CVE.
  
  WORKFLOW:
  1. ANALYZE CVE: Call 'lookup_vulnerability'.
  2. SCAN ENVIRONMENT: Call 'lookup_environment' with 'ALL'.
  3. MAP IMPACT: 
     - Filter assets that match the affected software/version.
     - For each matching asset, check its specific configuration (via 'lookup_environment' for that ID) and network zone.
     - Cross-reference with Evidence IDs (e.g., S02 for network access).
  4. RATE OVERALL RISK:
     - HIGH: At least one critical asset is confirmed exploitable AND would cause major business harm.
     - MEDIUM: Exploitable assets found, but impact is meaningful rather than catastrophic.
     - LOW: No matching assets found, or existing controls effectively mitigate the threat.
     - "Insufficient evidence" if you cannot determine the version of a critical asset.
  
  STRICT RULE: Cite Evidence IDs (S01-S06) and Asset IDs (W01-L04) for every claim.
  
  CRITICAL: Do not attempt to summarize or "draft" the final JSON assessment until you have called BOTH 'lookup_vulnerability' AND 'lookup_environment' (ALL). If you have not called them, call them now.`;

  const response = await model.invoke([
    { role: "system", content: systemPrompt },
    ...state.messages
  ]);

  return { 
    messages: [response],
    status: response.tool_calls?.length ? "collecting_evidence" : "drafting"
  };
}

const toolNodeWrapper = async (state: typeof AgentState.State) => {
  const { messages } = state;
  const lastMessage = messages[messages.length - 1];
  const toolResults = [];
  
  try {
    for (const call of lastMessage.tool_calls) {
      const tool = tools.find(t => t.name === call.name);
      if (tool) {
        const output = await tool.invoke(call.args);
        toolResults.push({ role: "tool", content: output, tool_call_id: call.id });
      }
    }
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : String(e);
    
    // Print in RED to the terminal for immediate visibility
    console.log(`${RED}❌ TOOL ERROR: ${errorMessage}${RESET}`);
    
    return { 
      messages: [{ 
        role: "tool", 
        content: `Error: ${errorMessage}`,
        tool_call_id: lastMessage.tool_calls[0].id 
      }] 
    };
  }
  
  return { messages: toolResults };
};

async function drafter(state: typeof AgentState.State) {
  const prompt = `Prepare the final Risk Assessment.
  
  OUTPUT REQUIREMENT:
  - You MUST output ONLY a valid JSON object.
  - DO NOT include any conversational text, markdown formatting, preambles, or postscripts.
  - The only text in the entire response must be the JSON object.
  
  REQUIRED JSON SCHEMA:
  {
    "asset_and_threat": {
      "asset_id": "string (e.g. W01)",
      "service_id": "string",
      "threat_weakness": "string (CVE ID and description)"
    },
    "decision": "High | Medium | Low | Insufficient Evidence | Manual Review Required",
    "rationale": {
      "applicability": "string",
      "impact": "string",
      "other_factors": "string",
      "policy_rule_applied": "string (describe which risk rating rule was used)"
    },
    "evidence_and_uncertainty": {
      "sources": ["string (e.g. NVD, S01, S02)"],
      "facts": ["string"],
      "assumptions": ["string"],
      "unknowns": ["string"],
      "confidence": "string (High/Medium/Low)",
      "evidence_status": "simulated | live | cached"
    },
    "action": {
      "recommended_next_step": "string",
      "evidence_needed_to_change_decision": "string"
    }
  }
  
  End your response with "SUBMIT FOR REVIEW".`;

  const response = await model.invoke([
    ...state.messages,
    { role: "system", content: prompt }
  ]);

  // POST-PROCESSING: Strip everything except the JSON and the "SUBMIT FOR REVIEW" tag
  let content = response.content;
  const jsonMatch = content.match(/\{[\s\S]*\}/);
  if (jsonMatch) {
    content = jsonMatch[0] + "\\n\\nSUBMIT FOR REVIEW";
  }

  return { 
    messages: [{ ...response, content }], 
    status: "awaiting_review" 
  };
}

// --- GRAPH ---
function route(state: typeof AgentState.State) {
  const lastMsg = state.messages[state.messages.length - 1];
  if (lastMsg.tool_calls?.length) return "tools";
  if (state.status === "awaiting_review") return "END";
  return "drafter";
}

const workflow = new StateGraph(AgentState)
  .addNode("analyzer", analyzer)
  .addNode("tools", toolNodeWrapper)
  .addNode("drafter", drafter)
  .addEdge("__start__", "analyzer")
  .addConditionalEdges("analyzer", route)
  .addEdge("tools", "analyzer")
  .addEdge("drafter", END);

const app = workflow.compile();

// --- CLI UI ---
async function main() {
  const rl = readline.createInterface({ input: inputStdin, output: outputStdout });
  console.log("\n--- Northbridge Env-Wide Risk Agent ---");
  
  let state = { messages: [], status: "start" };

  while (true) {
    const cveId = await rl.question("\nEnter CVE ID to assess environment (or 'exit') > ");
    if (cveId.toLowerCase() === "exit") break;
    if (!cveId) continue;

    state.messages.push({ role: "user", content: `Assess the risk of ${cveId} across the entire Northbridge environment.` });

    const result = await app.invoke(state);
    state = result;

    const lastMsg = state.messages[state.messages.length - 1];
    console.log(`\n[Agent]: ${lastMsg.content}`);

    if (state.status === "awaiting_review") {
      console.log("\n--- HUMAN REVIEW REQUIRED ---");
      const review = await rl.question("Do you approve this assessment? (yes/no/corrections) > ");
      if (review.toLowerCase() === "yes") {
        console.log("\nAssessment Approved.");
        state.status = "finalized";
      } else {
        console.log("\nIncorporating feedback...");
        state.messages.push({ role: "user", content: `Reviewer feedback: ${review}. Please revise.` });
        state.status = "start";
      }
    }
  }
  rl.close();
}

main().catch(console.error);
