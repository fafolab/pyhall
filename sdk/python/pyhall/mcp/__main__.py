"""Entry point for `python -m pyhall.mcp` and the `pyhall-mcp` command."""

from pyhall.mcp.server import run_stdio_loop


def main() -> None:
    run_stdio_loop()


if __name__ == "__main__":
    main()
