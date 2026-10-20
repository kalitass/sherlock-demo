# Sherlock — one-command operations. Requires Docker + uv.
H ?= An external actor brute-forced the administrator account and gained access

.PHONY: help up down wipe install mordor sigma hunt experiment dashboard mcp status schemas providers pull-watch stream-demo demo

help:
	@echo "make up         - start Elasticsearch + Kibana (Docker)"
	@echo "make install    - create the Python venv (uv sync)"
	@echo "make mordor     - ingest the public OTRF Security-Datasets (ATT&CK-labelled)"
	@echo "make sigma      - migrate Sigma detection rules into canonical n_* detections"
	@echo "make dashboard  - run the web dashboard (http://localhost:8080)"
	@echo "make hunt H='..'- run a hunt from the CLI"
	@echo "make experiment H='..' - run the same hunt twice and diff"
	@echo "make demo       - up + install + mordor + dashboard (full local bring-up)"
	@echo "make status     - cluster/index overview"
	@echo "make down       - stop containers   |   make wipe - stop + delete data"

up:
	docker compose up -d --build
	@echo "waiting for Elasticsearch…"
	@until curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; do sleep 3; done
	@echo "Elasticsearch is up on :9200 (Kibana on :5601, may take ~1 min more)"

down:
	docker compose down

wipe:
	docker compose down -v

install:
	uv sync

mordor: install
	uv run python -m cli mordor $(LABELS)

sigma: install
	uv run python -m cli sigma $(if $(LLM),--llm,) $(FILES)

hunt: install
	uv run python -m cli hunt "$(H)"

experiment: install
	uv run python -m cli experiment "$(H)" $(if $(LLM),,--no-llm)

dashboard: install
	uv run python -m cli dashboard

providers: install
	uv run python -m cli providers

mcp: install
	uv run python -m cli mcp

status:
	uv run python -m cli status

schemas:
	uv run python -m cli schemas

pull-watch: install
	uv run python -m ingestion.pull

stream-demo: install
	uv run python -m ingestion.stream --send $(FILE)

demo: up install mordor
	@echo "\n>>> Bring-up complete. Starting dashboard on http://localhost:8080\n"
	uv run python -m cli dashboard
