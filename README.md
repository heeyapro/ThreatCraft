<p align="center"> 
  <!-- 도구 로고 -->
  <img src="asset/logo_temp.png" width="20%">
</p>

<div align="center">

  <h1 align="center">ThreatCraft</h1>

  <p align="center">
    <a href="https://www.python.org/">
      <img src="https://img.shields.io/badge/Python-v3.10.19-blue?style=for-the-badge&logo=Python">
    </a>
    <a href="https://github.com/heeyapro/ULTARA/">
      <img src="https://img.shields.io/badge/Github-35495E?logo=GitHub&style=for-the-badge">
    </a>
    <a href="https://graphviz.org/">
      <img src="https://img.shields.io/badge/Graphviz-v14.1.5-green?style=for-the-badge&logo=diagrams.net&logoColor=white">
    </a>
  </p>
<br><b>ThreatCraft</b> is a hybrid threat modeling tool that combines rule-based reasoning with large language models to generate structurally valid and realistic attack paths, addressing limitations of prior approaches such as expert dependency, inconsistency, and hallucinated scenarios.
<br/>

<br>
<img src="https://raw.githubusercontent.com/amitmerchant1990/electron-markdownify/master/app/img/markdownify.gif" alt="Markdownify" width="100%">
</br>
</div>

<!-- TABLE OF CONTENTS -->
<h2 id="table-of-contents"> :book: Table of Contents</h2>

<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#overview"> ➤ Overview</a></li>
    <li><a href="#project-files-description"> ➤ Project Files Description</a></li>
    <li><a href="#installation"> ➤ Installation</a></li>
    <li><a href="#usage-example"> ➤ Usage Example </a></li>
    <li><a href="#contributors"> ➤ Contributors </a></li>
  </ol>
</details>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="overview"> :compass: Overview</h2>

<img src="asset/WorkFlow-1.png">

<!--  -->


<p align="justify">

ThreatCraft is a hybrid threat modeling framework that integrates a rule-based attack reasoning engine with LLM-based scenario generation. The system is designed to address two fundamental limitations in existing approaches: (i) rule-based systems require extensive manual rule engineering, and (ii) LLM-based approaches suffer from hallucinated or structurally invalid attack paths.

</p>

---

### 🔁 1. Rule-Based Engine Layer

<p align="justify">

The overall architecture shown in Figure above is organized as a sequential pipeline:

</p>

- 📌 <b>Input Data (DFD / System Description)</b>  
  → DataFlow Diagram(DFD), Attack Mode, Target Asset
  → (Figure: left-most input block)

- 📌 <b>Rule-Based Attack Engine</b>  
  → Constructs structured attack paths using:
  - Integrated Attack Library (MITRE ATT&CK, CVE, CWE, domain KBs)
  - Asset & attack-step dependency model  
  - Unified Kill Chain (UKC) phase structuring  
  → (Figure: upper-middle “Rule Engine” block which is composed of 'Attack Scenario' and 'Risk Value Determination' block)

- 📌 <b>Risk Assessment Module</b>  
  → Evaluates attack paths using:
  - Feasibility (attack vector: network/local/physical/etc.)
  - Impact (SFOP + asset criticality)  
  → (Figure: branch under rule engine → “Risk Matrix”)

---

### 🤖 2. LLM-Guided Threat Refinement Layer

<p align="justify">

The system-level outputs are not final results. They are used as grounded constraints for LLM-based refinement.

</p>

- 📌 <b>Reviewer Agent</b>  
  → Converts structured attack paths into natural-language reasoning  
  → Validates logical consistency against attack knowledge base  
  → (Figure: LLM block – “Reviewer”)

- 📌 <b>Generator Agent</b>  
  → Expands system-level paths into function-level attack scenarios  
  → Injects vulnerability context (CWE / CVE / EMB3D mapping)  
  → (Figure: LLM block – “Generator”)

- 📌 <b>Component-Specific Knowledge Injection</b>  
  → Embeds real-world vulnerability context:
  - MITRE EMB3D (hardware/software/network/application mapping)
  - CWE / CVE enrichment  
  → (Figure: CWE/CVE Mapping feeding LLM layer)

---

### 📊 3. Output 

<p align="justify">

The final output is a structured threat report that includes:

</p>

- 🧩 Function-level attack scenarios
- 🧩 System-level validated attack graph
- 🧩 Risk scores (feasibility × impact)
- 🧩 Asset-level vulnerability mapping

→ (Figure: bottom/right output block)

---

### 🎯 Key Insight of the Architecture

<p align="justify">

ThreatCraft is not a pure LLM system nor a pure rule engine. Instead, it is a <b>two-stage constrained generation framework</b> where:
</p>

- Rule-based reasoning defines the “what is possible”
- LLM defines the “how it actually happens”
- Knowledge base grounding ensures “real-world feasibility”

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="project-files-description"> :file_folder: Project Files Description</h2>

```bash
ThreatCraft/
├── asset/                          # Static assets (figures, logo, references)
│   ├── logo_temp.png               # Project logo used in README/UI
│   ├── WorkFlow-1.png              # System architecture diagram (paper figure)
│   └── UKC_document.pdf            # Unified Kill Chain reference document
│
├── code/                           # Core implementation directory
│   │
│   ├── frontend/                   # GUI + orchestration layer
│   │   ├── tool_attack_paths_v19.py        # Main entry point (GUI launcher)
│   │   ├── tool_threat_mapper_v7.py        # Middleware between GUI and backend
│   │   └── hierarchy_data_ver0.2.json      # CVE–CWE–EMB3D mapping dataset
│   │
│   └── backend/                    # Threat reasoning & attack graph engine
│       ├── parse_attack_graph_v37.py       # Core attack scenario generator
│       │
│       └── threat_library/         # Structured threat intelligence database
│           ├── asset_to_threats_ver0.3.json
│           │   # Maps assets → applicable threats & tactics
│           │
│           ├── attack_vector_feasibility_ver0.1.json
│           │   # Threat metadata (tactic, feasibility, attack vector)
│           │
│           ├── dependency.json
│           │   # Asset/threat dependency constraints for attack chaining
│           │
│           ├── impact_feasability_map.json
│           │   # Risk scoring model (severity × feasibility)
│           │
│           ├── impact_map.json
│           │   # SFOP impact model (Safety / Financial / Operational / Privacy)
│           │
│           └── threat_to_tactic_ver0.1.json
│               # Threat → MITRE ATT&CK tactic mapping & ordering logic
```

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="installation"> :gear: Installation</h2>

<p align="justify">
  Follow the steps below to set up and run <b>ThreatCraft</b> in your local environment.
</p>

<ol>
  <li>
    <b>Install Graphviz</b><br/>
    Download and install Graphviz from the official site:<br/>
    https://graphviz.org/download/<br/><br/>
    After installation, make sure to add Graphviz to your system <b>PATH</b> (required for rendering attack graphs).
  </li>

  <li>
    <b>Install Python dependencies</b><br/>
    Run the following command in your project environment:
    <pre><code>pip install graphviz pillow</code></pre>
  </li>

  <li>
    <b>Verify backend prerequisites</b><br/>
    Ensure Python version is <b>3.10+</b> and Graphviz is accessible from the terminal:
    <pre><code>dot -V</code></pre>
  </li>

  <li>
    <b>Run ThreatCraft</b><br/>
    Navigate to the frontend directory and execute:
    <pre><code>cd code/frontend
python tool_attack_paths_v19.py --backend ../backend/parse_attack_graph_v37.py</code></pre>
  </li>
</ol>

<p align="justify">
  Once executed successfully, the system will launch the ThreatCraft and the GUI will be displayed on your screen.
</p>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="usage-example"> :rocket: Usage Example</h2>

### 🎯 Scenario Definition: Remote Attack on Vehicle Door System

We assume an attacker attempting to remotely compromise a vehicle door control system.

- **Target Asset**: `Door`
- **Trust Boundary**: `External Vehicle Boundary`
- **Attack Mode**: `Remote`
<img src="asset/20260211_172126.png" alt="DFD" width="100%">

---

### **1. Launch ThreatCraft & Configure Analysis Context**

After starting the application, the GUI dashboard is displayed.

Configure the analysis environment as follows:

- 📂 **DFD File Selection**  
  Load the target system model (`TM7 file`) representing the vehicle architecture.

- 🧠 **LLM Configuration**  
  - Select LLM backend (e.g., GPT-based model)
  - Input valid API key

- 🎯 **Target Definition**
  - Select **Target Asset**: `Door`

- 🌐 **Trust Boundary Selection**
  - Define system boundary: `External Vehicle Boundary`

- ⚔️ **Attack Mode**
  - Set attacker capability: `Remote`

- ▶️ Click **`Run Analysis`**

> 📌 Note: All required threat intelligence libraries (CVE/CWE/EMB3D mappings, dependency graphs, risk models) are preloaded via *Library File Settings* by default.

<img src="asset/20260502_180259.png" alt="DFD" width="100%">

---

### **2. Configure Implementation Detail of Assets**

Next, we define the implementation details for each asset. 

For instance, as shown in the figure below a TCU may run a Linux operating system with multiple implementation characteristics:
- loadable kernel modules (PID-23L1) and
- Linux namespace isolation (PID-23L2). 

After adding the implementation details to the assets, click “OK”.

> 📌 Note: It is not mandatory to provide implementation details for all assets.
 
<img src="asset/20260502_181157.png" alt="config" width="100%">

---

### **3. Check the Analysis Result**

The result window consists of three tabs:

---

#### **1) Asset Mapping**
Each CWE threat is mapped to a specific asset. Note that CWE entries for an asset are not provided by default; they become available only after defining the asset’s implementation details, as described in Subsection 2 (“Configure Implementation Details of Assets”).

<img src="asset/20260502_183945.png" alt="analysis_result1" width="100%">

---

#### **2) Attack Paths**
Each identified attack path is summarised. Each path represents a unique combination of assets and threats.

<img src="asset/20260502_181549.png" alt="analysis_result2" width="100%">

---

#### **3) AI Analysis**
The AI analysis is divided into two levels:

---

##### **Vehicle-Level Review**
For each attack path, the tool assesses its likelihood (confidence level) and provides mitigation recommendations. Furthermore, it performs a comprehensive evaluation across all attack paths to identify and present the highest-risk path.

<img src="asset/20260502_185751.png" alt="analysis_result3" width="100%">

---

##### **Functional-Level Review**
The tool evaluates the most critical vulnerabilities within each asset in the aggregated attack tree from an SFOP (Safety, Financial, Operational, Privacy) perspective, and presents the results for each asset-specific vulnerability accordingly.

<img src="asset/20260502_185712.png" alt="analysis_result4" width="100%">


> 📌 Note: You could save its results into JSON, CSV respectively
  
![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)



<!-- OVERVIEW -->
<h2 id="contributors"> :busts_in_silhouette: Contributors</h2>

<div align="center">
<table>
  <tr>
    <td align="center">
      <a href="https://github.com/heeyapro">
        <img src="https://github.com/heeyapro.png" width="90px;" style="border-radius:50%;" />
      </a>
      <br />
      <b>Heeyapro</b>
      <hr style="margin:3px 0; border:0.5px solid #444; opacity:0.4;">
      🧠 Project Lead
      <hr style="margin:3px 0; border:0.5px solid #444; opacity:0.4;">
      📧 kangdohee1211@korea.ac.kr
    </td>
    <td align="center">
      <a href="https://github.com/sinse100">
        <img src="https://github.com/sinse100.png" width="90px;" style="border-radius:50%;" />
      </a>
      <br />
      <b>sinse100</b>
      <hr style="margin:3px 0; border:0.5px solid #444; opacity:0.4;">
      🔬 Co-Researcher
      <hr style="margin:3px 0; border:0.5px solid #444; opacity:0.4;">
      📧 sinse100@korea.ac.kr
    </td>
  </tr>
</table>
</div>
