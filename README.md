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
  TBD
</p>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="project-files-description"> :file_folder: Project Files Description</h2>

<p align="justify"> 
  TBD
</p>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="installation"> :gear: Installation</h2>
<!-- subsection 1. graphviz 설치 -->
<!-- https://graphviz.org/download/  가서 다운로드-->
<!-- Add Graphviz to the system PATH for all users -->

<!-- 필요한 Python 패키지 설치 -->
<!-- pip install Graphviz -->
<!-- pip install Pillow -->

<!-- 도구 실행 -->
<!-- code/frontend 에 가서 python tool_attack_paths_v19.py --backend ../backend/parse_attack_graph_v37.py 명령어 입력  -->



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

<p align="justify"> 
  TBD
</p>

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
