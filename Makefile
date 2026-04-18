.PHONY: help install test run-api run-dashboard run docker-up docker-down clean simulate

help:
	@echo "ExposeBrief — common commands"
	@echo ""
	@echo "  make install         Install Python deps"
	@echo "  make test            Run pytest suite"
	@echo "  make run-api         Run FastAPI on :8000"
	@echo "  make run-dashboard   Run Streamlit on :8501 (requires API running)"
	@echo "  make docker-up       Bring up full stack via docker compose"
	@echo "  make docker-down     Tear down docker stack"
	@echo "  make simulate        POST /simulate with 300 events (API must be running)"
	@echo "  make clean           Remove SQLite db and caches"

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v

run-api:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run-dashboard:
	streamlit run dashboard/app.py

docker-up:
	docker compose up --build

docker-down:
	docker compose down

simulate:
	curl -s -X POST http://localhost:8000/simulate \
	  -H "Content-Type: application/json" \
	  -d '{"n": 300}' | python -m json.tool

clean:
	rm -f data/exposebrief.db data/*.db-journal
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
