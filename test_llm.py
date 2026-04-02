"""Simple test script to verify the LLM API endpoint is reachable."""

import os
import sys

from dotenv import load_dotenv

load_dotenv()


def main():
    base_url = os.getenv("LLM_BASE_URL", "http://localhost:8080/v1")
    api_key = os.getenv("LLM_API_KEY", "not-needed")
    model = os.getenv("LLM_MODEL", "default-model")

    print(f"Testing LLM endpoint...")
    print(f"  Base URL : {base_url}")
    print(f"  Model    : {model}")
    print(f"  API Key  : {'***' + api_key[-4:] if len(api_key) > 8 else '(short/default)'}")
    print()

    try:
        from openai import OpenAI

        client = OpenAI(base_url=base_url, api_key=api_key)

        # Test 1: List models
        print("[1/2] Listing available models...")
        try:
            models = client.models.list()
            print(f"  [OK] {len(models.data)} model(s) available:")
            for m in models.data[:5]:
                print(f"    - {m.id}")
            if len(models.data) > 5:
                print(f"    ... and {len(models.data) - 5} more")
        except Exception as e:
            print(f"  [WARN] Could not list models: {e}")

        # Test 2: Simple completion
        print(f"\n[2/2] Sending test prompt to '{model}'...")
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Say 'hello' and nothing else."}],
            max_tokens=10,
        )
        reply = response.choices[0].message.content.strip()
        tokens_in = getattr(response.usage, "prompt_tokens", "?")
        tokens_out = getattr(response.usage, "completion_tokens", "?")
        print(f"  [OK] Response: \"{reply}\"")
        print(f"  [Tokens] {tokens_in} in / {tokens_out} out")

        print("\nAll checks passed. LLM endpoint is working.")

    except ImportError:
        print("ERROR: 'openai' package not installed. Run: pip install openai")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
