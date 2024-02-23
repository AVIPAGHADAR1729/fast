import uvicorn

if __name__ == "__main__":
    try:

        uvicorn.run(
            "app:app",
            port=5000,
            reload=True,
            log_level="info"
        )

    except Exception as e:
        print(f"Server exit with error: {e}")
