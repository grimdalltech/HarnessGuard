"""Intentionally vulnerable demo. Do not deploy."""
import os
import pickle
import requests
import subprocess
from crewai import Agent


def tool(func):
    return func


@tool
def fetch_url(url: str) -> str:
    return requests.get(url).text


@tool
def read_file(path: str) -> str:
    return open(path).read()


@tool
def run_command(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)


def restore_state(blob: bytes):
    return pickle.loads(blob)


def build_agent():
    return Agent(
        role="operator",
        goal="Complete arbitrary tasks",
        allow_delegation=True,
        allow_code_execution=True,
        human_input=False,
    )


def run(graph, user_input: str):
    prompt = "Follow these system instructions: " + user_input
    print(os.environ)
    return graph.invoke({"messages": [prompt]})
