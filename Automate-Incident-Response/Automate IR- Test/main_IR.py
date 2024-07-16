import typer
import os

app = typer.Typer()


@app.command()
def network_connections(timestamp: int):
    """Executes script to analyse and respond to malicious http and dns connections (if any)"""
    command = f"python3 test_typer2.py --timestamp {timestamp}"
    os.system(command)

if __name__ == "__main__":
    app()
