# 🛡️ Agent Memory Guard - Jupyter Notebooks 

This folder contains 4 notebooks that give a detailed view of the Agent Memory Guard in action. It is for developers, security engineers, and contributors.

| Notebook | Description | Audience |
|---|---|---|
| [quickstart.ipynb](./quickstart.ipynb) | Getting started with Agent Memory Guard | Anyone |
| [attack_simulation.ipynb](./attack_simulation.ipynb) | Simulating various attacks and showing the guard in action | Contributors, developers |
| [forensics_and_rollback.ipynb](./forensics_and_rollback.ipynb) | Running a forensic analysis after an attack and rolling back to a saved state. | Security engineers |
| [langchain_integration.ipynb](./langchain_integration.ipynb) | Integrating Agent Memory Guard using Langchain | Developers |

## How to Run 

```bash  
# cloning the repository 
git clone https://github.com/OWASP/www-project-agent-memory-guard.git && cd www-project-agent-memory-guard

# installing dependencies 
pip install -e ".[dev]"

# launching notebooks 
jupyter notebook examples/notebooks/
```

