#!/usr/bin/env python3
"""
bootstrap.py — HuggingFace Worker entry point

Delegates all execution to worker_logic.run().

Usage:
    python3 bootstrap.py <op> [options]

    python3 bootstrap.py run_inference --model-id "gpt2" --inputs "The quick brown fox"
    python3 bootstrap.py run_text_generation --model-id "mistralai/Mistral-7B-Instruct-v0.3" --prompt "Hello!"
    python3 bootstrap.py run_summarization --text "Long article text here..."
    python3 bootstrap.py run_classification --text "I love this!" --labels '["positive","negative"]'
    python3 bootstrap.py run_embeddings --texts '["Hello world","Foo bar"]'
    python3 bootstrap.py list_models --task text-generation --limit 10
    python3 bootstrap.py get_model_info --model-id "gpt2"
    python3 bootstrap.py search_models --query "sentence transformers" --limit 5
    python3 bootstrap.py list_spaces --search "stable diffusion" --limit 10
    python3 bootstrap.py get_space_info --space-id "stabilityai/stable-diffusion"
    python3 bootstrap.py list_datasets --search "common voice" --limit 10
    python3 bootstrap.py get_dataset_info --dataset-id "mozilla-foundation/common_voice_11_0"
    python3 bootstrap.py run_space_api --space-id "ResembleAI/chatterbox" --api-name "/generate" --inputs '["Hello!"]'

Prerequisites:
    pip install requests>=2.28.0 gradio_client>=1.0.0 pyhall-wcp>=0.2.2
    export HF_TOKEN=<your-huggingface-token>
    export PYHALL_ENV=dev   # or stage / prod
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the code directory is on the path when run directly
_CODE_DIR = Path(__file__).resolve().parent
if str(_CODE_DIR) not in sys.path:
    sys.path.insert(0, str(_CODE_DIR))

from worker_logic import run

if __name__ == "__main__":
    run()
