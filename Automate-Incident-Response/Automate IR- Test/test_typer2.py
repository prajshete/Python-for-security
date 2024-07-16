import typer

def main(timestamp: int):
    print(f"Timestamp received: {timestamp}")

if __name__ == "__main__":
    typer.run(main)
