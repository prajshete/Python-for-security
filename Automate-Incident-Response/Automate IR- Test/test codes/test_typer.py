import typer
import os
import asyncio
import time

# Initialize Typer app
app = typer.Typer()


def print_time(timestamp: str):
     if timestamp.endswith('h'):
            hours = int(timestamp[:-1])
     print(f"Running example command with timestamp: {hours}h")
     
# Example function using Typer as a command
@app.command()
def main(timestamp: str = typer.Option(..., help="Timestamp for the query")):
    print_time(timestamp)

if __name__ == "__main__":
    app()
