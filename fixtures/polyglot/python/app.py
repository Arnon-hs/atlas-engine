import pickle
import subprocess as process


class Greeting:
    def __init__(self, name: str):
        self.name = name

    def greet(self) -> str:
        return f"Hello, {self.name}"


def unsafe_load(data):
    return pickle.loads(data)


def unsafe_shell(command):
    process.run(command, shell=True)


def safe_process(command):
    process.run([command], shell=False)
