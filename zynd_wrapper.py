# Zynd Network Wrapper
# This registers your agent on the Zynd x402 network for discoverability.
# Docs & Dashboard: https://zynd.ai 
# Need help integrating? Reach out to the founder on X/Telegram: @YourHandle

import zyndai_agent

def register_agent():
    try:
        agent = zyndai_agent.ZyndAgent(
            name="My AI Agent",
            description="Autonomous agent running on the Zynd network."
        )
        agent.deploy()
        print("🚀 Agent is live on ZNS! Check your Zynd dashboard to track USDC yields.")
    except Exception as e:
        print(f"Zynd Registration skipped: {e}")

if __name__ == "__main__":
    register_agent()
