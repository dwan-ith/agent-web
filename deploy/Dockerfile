FROM python:3.13.5-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/agent-web

COPY deploy/requirements.lock /opt/agent-web/deploy/requirements.lock
RUN python -m pip install --no-cache-dir -r deploy/requirements.lock

COPY libagentweb/python /opt/agent-web/libagentweb/python
COPY agent-web-server/python /opt/agent-web/agent-web-server/python
COPY sites/moltbook/python /opt/agent-web/sites/moltbook/python
COPY sites/forecast/python /opt/agent-web/sites/forecast/python
COPY sites/registry/python /opt/agent-web/sites/registry/python
COPY agent-web-browser/python /opt/agent-web/agent-web-browser/python

RUN python -m pip install --no-cache-dir --no-deps \
      ./libagentweb/python \
      ./agent-web-server/python \
      ./sites/moltbook/python \
      ./sites/forecast/python \
      ./sites/registry/python \
      ./agent-web-browser/python \
    && addgroup --system --gid 10001 agentweb \
    && adduser --system --uid 10001 --ingroup agentweb \
         --home /var/lib/agent-web agentweb \
    && mkdir -p /var/lib/agent-web \
    && chown -R agentweb:agentweb /var/lib/agent-web

USER 10001:10001
WORKDIR /var/lib/agent-web

ENTRYPOINT ["python", "-m"]
